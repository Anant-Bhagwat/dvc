import fs from 'node:fs';
import path from 'node:path';
import nodeCrypto from 'node:crypto';
import 'dotenv/config';
import pino from 'pino';
import { importPKCS8, importJWK } from 'jose';
import { parsed ,claimName,csv,boolish, jwtCreateSchema} from '../validations/jwt.validation.js';

export const ALG = 'ES256';


if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`);
    console.error(`Invalid environment configuration:\n${issues.join('\n')}`);
    process.exit(1);
}

const fail = (message) => {
    console.error(`Invalid configuration: ${message}`);
    process.exit(1);
};

const config = parsed.data;

if (config.JWT_MAX_EXPIRY < config.JWT_DEFAULT_EXPIRY) {
    fail('JWT_MAX_EXPIRY must be >= JWT_DEFAULT_EXPIRY');
}
if (!config.JWT_PRIVATE_KEY && !config.JWT_PRIVATE_KEY_PATH) {
    fail('provide JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH (run `npm run keys:generate`)');
}
if (config.JWT_TRUSTED_ISSUERS.length === 0) {
    config.JWT_TRUSTED_ISSUERS = [config.JWT_ISSUER];
}
if (config.NODE_ENV === 'production') {
    if (!config.AUTH_ENABLED) fail('AUTH_ENABLED must be true in production');
    if (config.API_ACCESS_TOKENS.length === 0) fail('API_ACCESS_TOKENS is empty while auth is enabled');
    if (config.API_ACCESS_TOKENS.some((t) => t.length < 32)) {
        fail('every API_ACCESS_TOKENS entry must be at least 32 characters in production');
    }
    if (new Set(config.API_ACCESS_TOKENS).size !== config.API_ACCESS_TOKENS.length) {
        fail('API_ACCESS_TOKENS contains duplicate entries');
    }
}

export const env = Object.freeze(config);

export const jwtCreate = jwtCreateSchema(env.JWT_MAX_EXPIRY);

export const logger = pino({
    level: env.LOG_LEVEL,
    redact: {
        paths: [
            'req.headers.authorization',
            'req.headers.cookie',
            'headers.authorization',
            'token',
            '*.token',
            'privateKey',
            '*.privateKey',
            'password',
            '*.password',
        ],
        censor: '[REDACTED]',
    },
    base: { service: 'jwt-api' },
    timestamp: pino.stdTimeFunctions.isoTime,
    transport:
        env.NODE_ENV === 'development'
            ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'SYS:standard' } }
            : undefined,
});

let keyState = null;

function readPrivatePem() {
    if (env.JWT_PRIVATE_KEY) {
        return { pem: env.JWT_PRIVATE_KEY.replace(/\\n/g, '\n'), source: 'env' };
    }

    const keyPath = path.resolve(process.cwd(), env.JWT_PRIVATE_KEY_PATH);

    if (!fs.existsSync(keyPath)) {
        throw new Error(`Issuer private key not found at ${keyPath}. Run \`npm run keys:generate\`.`);
    }

    if (process.platform !== 'win32' && fs.statSync(keyPath).mode & 0o077) {
        logger.warn({ path: keyPath }, 'Issuer private key is group/world readable; tighten to 0600');
    }

    return { pem: fs.readFileSync(keyPath, 'utf8'), source: keyPath };
}

export async function initKeys() {
    if (keyState) return keyState;

    const { pem, source } = readPrivatePem();

    let privateKey;
    try {
        privateKey = await importPKCS8(pem, ALG);
    } catch (err) {
        throw new Error(`Failed to import issuer private key as ${ALG} (PKCS#8 expected): ${err.message}`);
    }

    let jwk;
    try {
        jwk = nodeCrypto.createPublicKey(nodeCrypto.createPrivateKey(pem)).export({ format: 'jwk' });
        if ('d' in jwk) throw new Error('derived public JWK unexpectedly contains `d`');
    } catch (err) {
        throw new Error(`Failed to derive the issuer public key: ${err.message}`);
    }

    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
        throw new Error(`Issuer key must be EC P-256 for ES256, got kty=${jwk.kty} crv=${jwk.crv}`);
    }

    const publicJwk = Object.freeze({
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        alg: ALG,
        use: 'sig',
        kid: env.JWT_KEY_ID,
    });

    if (env.JWT_PUBLIC_KEY_PATH) {
        const pubPath = path.resolve(process.cwd(), env.JWT_PUBLIC_KEY_PATH);
        if (fs.existsSync(pubPath)) {
            const loaded = nodeCrypto
                .createPublicKey(fs.readFileSync(pubPath, 'utf8'))
                .export({ format: 'jwk' });
            if (loaded.x !== publicJwk.x || loaded.y !== publicJwk.y) {
                throw new Error(
                    'JWT_PUBLIC_KEY_PATH does not match the private key. ' +
                    'Distributing it would make every issued token unverifiable.',
                );
            }
        }
    }

    keyState = Object.freeze({
        privateKey,
        publicJwk,
        verificationKey: await importJWK(publicJwk, ALG),
    });

    logger.info(
        { kid: publicJwk.kid, alg: ALG, keySource: source === 'env' ? 'env' : 'file' },
        'JWT issuer key loaded',
    );

    return keyState;
}

function requireKeys() {
    if (!keyState) throw new Error('JWT keys not initialised. Call initKeys() during bootstrap.');
    return keyState;
}

export const getSigningKey = () => requireKeys().privateKey;

export const getKeyId = () => requireKeys().publicJwk.kid;

export function resolveVerificationKey(kid) {
    const state = requireKeys();
    if (kid && kid !== state.publicJwk.kid) return null;
    return state.verificationKey;
}
