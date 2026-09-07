import crypto from 'node:crypto';
import { SignJWT, compactVerify, decodeProtectedHeader } from 'jose';

import {
  ALG,
  FORBIDDEN_KEYS,
  PROTECTED_CLAIMS,
  env,
  logger,
  getSigningKey,
  getKeyId,
  resolveVerificationKey,
} from './config.js';

export class AppError extends Error {
  constructor(message, { code = 'INTERNAL_ERROR', httpStatus = 500, details = null, expose = true } = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.httpStatus = httpStatus;
    this.details = details;
    this.expose = expose;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message, details = null) {
    super(message, { code: 'VALIDATION_ERROR', httpStatus: 400, details });
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Authentication required') {
    super(message, { code: 'UNAUTHORIZED', httpStatus: 401 });
  }
}

export class VerificationError extends AppError {
  constructor(message, reason = 'VERIFICATION_FAILED', details = null) {
    super(message, { code: reason, httpStatus: 400, details });
    this.reason = reason;
  }
}

export const VERIFY_REASONS = Object.freeze({
  MALFORMED_JWS: 'MALFORMED_JWS',
  UNSUPPORTED_ALGORITHM: 'UNSUPPORTED_ALGORITHM',
  UNSUPPORTED_TYP: 'UNSUPPORTED_TYP',
  UNSAFE_HEADER: 'UNSAFE_HEADER',
  UNKNOWN_KEY_ID: 'UNKNOWN_KEY_ID',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  UNTRUSTED_ISSUER: 'UNTRUSTED_ISSUER',
  CREDENTIAL_EXPIRED: 'CREDENTIAL_EXPIRED',
  CREDENTIAL_NOT_YET_VALID: 'CREDENTIAL_NOT_YET_VALID',
  INVALID_IAT: 'INVALID_IAT',
  MISSING_CLAIM: 'MISSING_CLAIM',
  HOLDER_BINDING_FAILED: 'HOLDER_BINDING_FAILED',
});

const KEY_SOURCE_HEADERS = ['jwk', 'jku', 'x5u', 'x5c', 'x5t', 'x5t#S256'];

function findForbiddenKey(node, depth = 0) {
  if (depth > 32 || node === null || typeof node !== 'object') return null;
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = findForbiddenKey(item, depth + 1);
      if (found) return found;
    }
    return null;
  }
  for (const key of Object.keys(node)) {
    if (FORBIDDEN_KEYS.includes(key)) return key;
    const found = findForbiddenKey(node[key], depth + 1);
    if (found) return found;
  }
  return null;
}

export { PROTECTED_CLAIMS };

export async function createJwt({
  subject = null,
  audience = null,
  claims = {},
  data = undefined,
  expiresIn = env.JWT_DEFAULT_EXPIRY,
  notBefore = null,
} = {}) {
  const attempted = PROTECTED_CLAIMS.filter((c) => Object.hasOwn(claims, c));
  if (attempted.length > 0) {
    throw new ValidationError('Reserved claims cannot be set through `claims`', { reserved: attempted });
  }

  const forbidden = findForbiddenKey(claims);
  if (forbidden) {
    throw new ValidationError('Claims must not contain prototype-polluting keys', { key: forbidden });
  }

  const lifetime = Math.min(expiresIn, env.JWT_MAX_EXPIRY);
  if (lifetime < 60) throw new ValidationError('Token lifetime must be at least 60 seconds');

  if (notBefore !== null && notBefore >= lifetime) {
    throw new ValidationError('notBefore must be shorter than the token lifetime', {
      notBefore,
      lifetime,
    });
  }

  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + lifetime;
  const jwtId = crypto.randomUUID();

  const payload = { ...claims, iss: env.JWT_ISSUER, iat: issuedAt, exp: expiresAt, jti: jwtId };
  if (subject) payload.sub = subject;
  if (audience) payload.aud = audience;
  if (notBefore) payload.nbf = issuedAt + notBefore;
  if (data !== undefined) payload[env.JWT_DATA_CLAIM] = data;

  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: ALG, typ: env.JWT_TYP, kid: getKeyId() })
    .sign(getSigningKey());

  logger.info({ jti: jwtId, audience, expiresAt, customClaims: Object.keys(claims) }, 'JWT issued');

  return { token, jwtId, issuedAt, expiresAt, payload };
}

export async function verifyJwt(token, options = {}) {
  const {
    trustedIssuers = env.JWT_TRUSTED_ISSUERS,
    expectedAudience = null,
    expectedSubject = null,
  } = options;

  if (typeof token !== 'string' || token.split('.').length !== 3) {
    throw new VerificationError(
      'Token is not a compact JWS (expected three dot-separated segments)',
      VERIFY_REASONS.MALFORMED_JWS,
    );
  }

  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    throw new VerificationError('Unable to decode the token header', VERIFY_REASONS.MALFORMED_JWS);
  }

  if (header.alg !== ALG) {
    throw new VerificationError(
      `Unsupported signing algorithm: expected ${ALG}`,
      VERIFY_REASONS.UNSUPPORTED_ALGORITHM,
      { received: header.alg ?? null },
    );
  }

  if (header.typ !== env.JWT_TYP) {
    throw new VerificationError(
      `Unsupported token type: expected ${env.JWT_TYP}`,
      VERIFY_REASONS.UNSUPPORTED_TYP,
      { received: header.typ ?? null },
    );
  }

  const attackerKeyHeader = KEY_SOURCE_HEADERS.find((h) => header[h] !== undefined);
  if (attackerKeyHeader) {
    throw new VerificationError(
      'Token header must not carry its own key material',
      VERIFY_REASONS.UNSAFE_HEADER,
      { header: attackerKeyHeader },
    );
  }

  if (header.crit !== undefined) {
    throw new VerificationError(
      'Token header declares unsupported critical extensions',
      VERIFY_REASONS.UNSAFE_HEADER,
    );
  }

  const key = resolveVerificationKey(header.kid);
  if (!key) {
    throw new VerificationError(
      'Signing key is not recognised by this verifier',
      VERIFY_REASONS.UNKNOWN_KEY_ID,
      { kid: header.kid ?? null },
    );
  }

  let payload;
  try {
    const { payload: bytes } = await compactVerify(token, key, { algorithms: [ALG] });
    payload = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new VerificationError('Token signature verification failed', VERIFY_REASONS.INVALID_SIGNATURE);
  }

  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new VerificationError('Token payload is not a JSON object', VERIFY_REASONS.MALFORMED_JWS);
  }

  for (const key of FORBIDDEN_KEYS) {
    if (Object.hasOwn(payload, key)) {
      delete payload[key];
      logger.warn({ key }, 'Dropped a prototype-polluting claim from a verified token');
    }
  }

  if (!payload.iss) {
    throw new VerificationError('Token is missing the `iss` claim', VERIFY_REASONS.MISSING_CLAIM);
  }
  if (!trustedIssuers.includes(payload.iss)) {
    throw new VerificationError('Token issuer is not trusted', VERIFY_REASONS.UNTRUSTED_ISSUER, {
      iss: payload.iss,
    });
  }

  const now = Math.floor(Date.now() / 1000);
  const skew = env.JWT_CLOCK_SKEW;

  if (typeof payload.iat !== 'number') {
    throw new VerificationError('Token is missing a numeric `iat`', VERIFY_REASONS.INVALID_IAT);
  }
  if (payload.iat > now + skew) {
    throw new VerificationError('Token `iat` is in the future', VERIFY_REASONS.INVALID_IAT);
  }

  if (typeof payload.exp !== 'number') {
    throw new VerificationError('Token is missing a numeric `exp`', VERIFY_REASONS.MISSING_CLAIM);
  }
  if (payload.exp <= now - skew) {
    throw new VerificationError('Token has expired', VERIFY_REASONS.CREDENTIAL_EXPIRED, {
      exp: payload.exp,
      now,
    });
  }
  if (typeof payload.nbf === 'number' && payload.nbf > now + skew) {
    throw new VerificationError('Token is not yet valid', VERIFY_REASONS.CREDENTIAL_NOT_YET_VALID);
  }

  if (expectedAudience) {
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud].filter(Boolean);
    if (!audiences.includes(expectedAudience)) {
      throw new VerificationError('Token audience mismatch', VERIFY_REASONS.HOLDER_BINDING_FAILED, {
        aud: payload.aud ?? null,
      });
    }
  }
  if (expectedSubject && payload.sub !== expectedSubject) {
    throw new VerificationError('Token subject mismatch', VERIFY_REASONS.HOLDER_BINDING_FAILED);
  }

  logger.info({ jti: payload.jti, iss: payload.iss }, 'JWT verified');

  return { valid: true, header, payload };
}
