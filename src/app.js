import crypto from 'node:crypto';
import express, { Router } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

import { FORBIDDEN_KEYS, PROTECTED_CLAIMS, env, logger } from './config.js';
import { AppError, UnauthorizedError, ValidationError, createJwt, verifyJwt } from './jwt.js';

export const CLAIM_LIMITS = Object.freeze({
  MAX_TOP_LEVEL_KEYS: 32,
  MAX_KEY_LENGTH: 64,
  MAX_STRING_LENGTH: 2048,
  MAX_ARRAY_LENGTH: 50,
  MAX_DEPTH: 5,
  MAX_SERIALIZED_BYTES: 8192,
});

const CORRELATION_ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

const claimKey = z
  .string()
  .max(CLAIM_LIMITS.MAX_KEY_LENGTH)
  .refine((k) => !FORBIDDEN_KEYS.includes(k), 'prototype-polluting keys are not allowed');

const jsonValue = z.lazy(() =>
  z.union([
    z.string().max(CLAIM_LIMITS.MAX_STRING_LENGTH),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(jsonValue).max(CLAIM_LIMITS.MAX_ARRAY_LENGTH),
    z.record(claimKey, jsonValue),
  ]),
);

function structureDepth(node, depth = 1) {
  if (node === null || typeof node !== 'object') return depth;
  const children = Array.isArray(node) ? node : Object.values(node);
  if (children.length === 0) return depth;
  return children.reduce((max, child) => Math.max(max, structureDepth(child, depth + 1)), depth);
}

const bindingValue = z.string().trim().min(1).max(256).optional();

function withAliases(schema, pairs) {
  const checked = pairs.reduce(
    (acc, [canonical, alias]) =>
      acc.refine(
        (body) =>
          body[canonical] === undefined || body[alias] === undefined || body[canonical] === body[alias],
        {
          path: [alias],
          message: `\`${canonical}\` and \`${alias}\` set the same claim and must not disagree`,
        },
      ),
    schema,
  );

  return checked.transform((body) => {
    const normalized = { ...body };
    for (const [canonical, alias] of pairs) {
      const value = normalized[canonical] ?? normalized[alias];
      delete normalized[alias];
      if (value !== undefined) normalized[canonical] = value;
    }
    return normalized;
  });
}

export const jwtCreateSchema = withAliases(
  z
    .object({
      subject: bindingValue,
      audience: bindingValue,
      expectedSubject: bindingValue,
      expectedAudience: bindingValue,

      claims: z
        .record(claimKey, jsonValue)
        .refine((c) => Object.keys(c).length <= CLAIM_LIMITS.MAX_TOP_LEVEL_KEYS, {
          message: `At most ${CLAIM_LIMITS.MAX_TOP_LEVEL_KEYS} top-level custom claims`,
        })
        .refine((c) => !Object.keys(c).some((k) => PROTECTED_CLAIMS.includes(k)), {
          message: `These claims are set by the issuer and cannot be supplied: ${PROTECTED_CLAIMS.join(', ')}`,
        })
        .refine((c) => structureDepth(c) <= CLAIM_LIMITS.MAX_DEPTH, {
          message: `Claims may nest at most ${CLAIM_LIMITS.MAX_DEPTH} levels deep`,
        })
        .refine((c) => Buffer.byteLength(JSON.stringify(c), 'utf8') <= CLAIM_LIMITS.MAX_SERIALIZED_BYTES, {
          message: `Serialized claims must not exceed ${CLAIM_LIMITS.MAX_SERIALIZED_BYTES} bytes`,
        })
        .optional(),

      data: z.any().optional(),

      expiresIn: z.coerce
        .number()
        .int()
        .min(60, 'expiresIn must be at least 60 seconds')
        .max(env.JWT_MAX_EXPIRY, `expiresIn must not exceed ${env.JWT_MAX_EXPIRY} seconds`)
        .optional(),

      notBefore: z.coerce.number().int().min(0).max(env.JWT_MAX_EXPIRY).optional(),
    })
    .strict(),
  [
    ['subject', 'expectedSubject'],
    ['audience', 'expectedAudience'],
  ],
);

export const jwtVerifySchema = withAliases(
  z
    .object({
      token: z.string().min(20).max(64 * 1024),
      expectedAudience: bindingValue,
      expectedSubject: bindingValue,
      audience: bindingValue,
      subject: bindingValue,
    })
    .strict(),
  [
    ['expectedAudience', 'audience'],
    ['expectedSubject', 'subject'],
  ],
);

function correlationId(req, res, next) {
  const supplied = req.get('x-correlation-id');
  req.correlationId = CORRELATION_ID_RE.test(supplied ?? '') ? supplied : crypto.randomUUID();
  res.set('x-correlation-id', req.correlationId);
  next();
}

function noStore(_req, res, next) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  next();
}

function requireJsonBody(req, _res, next) {
  if (!req.is('application/json')) {
    return next(
      new AppError('Content-Type must be application/json', {
        code: 'UNSUPPORTED_MEDIA_TYPE',
        httpStatus: 415,
      }),
    );
  }
  return next();
}

function validateBody(schema) {
  return (req, _res, next) => {
    const result = schema.safeParse(req.body ?? {});
    if (!result.success) {
      const details = result.error.issues.map((issue) => ({
        field: issue.path.join('.') || '(body)',
        message: issue.message,
      }));
      return next(new ValidationError('Request validation failed', details));
    }
    req.body = result.data;
    return next();
  };
}

const digest = (value) => crypto.createHash('sha256').update(value, 'utf8').digest();

function tokenMatches(presented) {
  const a = digest(presented);
  let matched = false;
  for (const configured of env.API_ACCESS_TOKENS) {
    if (crypto.timingSafeEqual(a, digest(configured))) matched = true;
  }
  return matched;
}

function requireAuth(req, _res, next) {
  if (!env.AUTH_ENABLED) {
    req.auth = { subject: 'anonymous', authenticated: false };
    return next();
  }

  const header = req.get('authorization') ?? '';
  const [scheme, ...rest] = header.split(' ');
  const token = /^Bearer$/i.test(scheme) ? rest.join(' ').trim() : '';

  if (!token) return next(new UnauthorizedError('Missing or malformed Authorization header'));

  if (!tokenMatches(token)) {
    logger.warn(
      { ip: req.ip, path: req.path, correlationId: req.correlationId },
      'Rejected request with invalid access token',
    );
    return next(new UnauthorizedError('Invalid access token'));
  }

  req.auth = { subject: 'api-client', authenticated: true };
  return next();
}

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const createToken = asyncHandler(async (req, res) => {
  const { subject, audience, claims, data, expiresIn, notBefore } = req.body;
  const result = await createJwt({ subject, audience, claims, data, expiresIn, notBefore });

  res.status(201).json({
    status: 'success',
    data: {
      token: result.token,
      token_id: result.jwtId,
      issued_at: new Date(result.issuedAt * 1000).toISOString(),
      expires_at: new Date(result.expiresAt * 1000).toISOString(),
      token_type: 'Bearer',
      expires_in: result.expiresAt - result.issuedAt,
    },
    correlationId: req.correlationId,
  });
});

const verifyToken = asyncHandler(async (req, res) => {
  const { token, expectedAudience, expectedSubject } = req.body;
  const result = await verifyJwt(token, { expectedAudience, expectedSubject });

  const { iss, sub, aud, exp, nbf, iat, jti, ...custom } = result.payload;
  const dataClaim = env.JWT_DATA_CLAIM;
  const hasData = Object.hasOwn(custom, dataClaim);
  const data = hasData ? custom[dataClaim] : null;
  if (hasData) delete custom[dataClaim];

  res.status(200).json({
    status: 'success',
    data: {
      valid: true,
      header: { alg: result.header.alg, typ: result.header.typ, kid: result.header.kid },
      issuer: iss,
      subject: sub ?? null,
      audience: aud ?? null,
      token_id: jti ?? null,
      issued_at: new Date(iat * 1000).toISOString(),
      expires_at: new Date(exp * 1000).toISOString(),
      not_before: typeof nbf === 'number' ? new Date(nbf * 1000).toISOString() : null,
      claims: custom,
      data,
    },
    correlationId: req.correlationId,
  });
});

function notFoundHandler(req, res) {
  res.status(404).json({
    status: 'error',
    error: { code: 'ROUTE_NOT_FOUND', message: `No route matches ${req.method} ${req.path}` },
    correlationId: req.correlationId,
  });
}

// eslint-disable-next-line no-unused-vars -- Express identifies error handlers by arity
function errorHandler(err, req, res, _next) {
  const correlationId = req.correlationId;

  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({
      status: 'error',
      error: { code: 'MALFORMED_JSON', message: 'Request body is not valid JSON' },
      correlationId,
    });
  }

  if (err?.type === 'entity.too.large') {
    return res.status(413).json({
      status: 'error',
      error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds the configured limit' },
      correlationId,
    });
  }

  if (err instanceof AppError) {
    logger[err.httpStatus >= 500 ? 'error' : 'warn'](
      {
        correlationId,
        code: err.code,
        httpStatus: err.httpStatus,
        path: req.path,
        err: err.httpStatus >= 500 ? err.message : undefined,
      },
      'Request failed',
    );

    return res.status(err.httpStatus).json({
      status: 'error',
      error: {
        code: err.code,
        message: err.expose ? err.message : 'An internal error occurred',
        ...(err.expose && err.details ? { details: err.details } : {}),
      },
      correlationId,
    });
  }

  logger.error({ correlationId, err: err?.message, stack: err?.stack, path: req.path }, 'Unhandled error');

  return res.status(500).json({
    status: 'error',
    error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred' },
    correlationId,
  });
}

export function createApp() {
  const app = express();

  app.set('trust proxy', env.TRUST_PROXY);
  app.set('query parser', 'simple');
  app.set('etag', false);
  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
      hsts: env.NODE_ENV === 'production' ? { maxAge: 31_536_000, includeSubDomains: true } : false,
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
    }),
  );

  app.use(correlationId);

  const limitMessage = (code, message) => ({ status: 'error', error: { code, message } });

  app.use(
    '/api/',
    rateLimit({
      windowMs: env.RATE_LIMIT_WINDOW_MS,
      max: env.RATE_LIMIT_MAX,
      standardHeaders: true,
      legacyHeaders: false,
      message: limitMessage('RATE_LIMITED', 'Too many requests'),
    }),
  );

  const authLimiter = rateLimit({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    max: env.AUTH_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    requestWasSuccessful: (_req, res) => res.statusCode !== 401,
    message: limitMessage('TOO_MANY_FAILED_AUTH', 'Too many failed authentication attempts'),
  });

  const jwtRoutes = Router();
  jwtRoutes.use(
    noStore,
    authLimiter,
    requireAuth,
    requireJsonBody,
    express.json({ limit: env.JSON_BODY_LIMIT, strict: true, type: 'application/json' }),
  );
  jwtRoutes.post('/create', validateBody(jwtCreateSchema), createToken);
  jwtRoutes.post('/verify', validateBody(jwtVerifySchema), verifyToken);

  app.use('/api/v1/jwt', jwtRoutes);

  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'success', data: { service: 'jwt-api', uptime: process.uptime() } });
  });

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

export default createApp;
