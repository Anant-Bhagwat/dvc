import { z } from 'zod';
import { FORBIDDEN_KEYS, PROTECTED_CLAIMS } from '../constants/jwt.constants.js';

export const boolish = (def) =>
    z
        .string()
        .optional()
        .transform((v) => (v === undefined ? def : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())));

export const csv = z
    .string()
    .optional()
    .transform((v) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean));

export const claimName = z
    .string()
    .min(1)
    .max(64)
    .regex(/^[A-Za-z0-9_.:-]+$/, 'must be alphanumeric with _ . : - only')
    .refine((v) => !FORBIDDEN_KEYS.includes(v), 'must not be a prototype-polluting key')
    .refine((v) => !PROTECTED_CLAIMS.includes(v), 'must not be a registered JWT claim');

export const parsed = z
    .object({
        NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
        PORT: z.coerce.number().int().min(1).max(65535).default(3000),
        LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
        TRUST_PROXY: z.coerce.number().int().min(0).max(10).default(0),

        JWT_ISSUER: z.string().url(),
        JWT_KEY_ID: z.string().min(1).max(128).default('jwt-signing-key-01'),
        JWT_PRIVATE_KEY_PATH: z.string().optional(),
        JWT_PUBLIC_KEY_PATH: z.string().optional(),
        JWT_PRIVATE_KEY: z.string().optional(),
        JWT_TYP: z.string().min(1).max(64).default('JWT'),

        JWT_DEFAULT_EXPIRY: z.coerce.number().int().min(60).default(3600),
        JWT_MAX_EXPIRY: z.coerce.number().int().min(60).default(86400),
        JWT_CLOCK_SKEW: z.coerce.number().int().min(0).max(600).default(60),
        JWT_TRUSTED_ISSUERS: csv,
        JWT_DATA_CLAIM: claimName.default('data'),

        JSON_BODY_LIMIT: z.string().default('1mb'),

        API_ACCESS_TOKENS: csv,
        AUTH_ENABLED: boolish(true),

        RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).default(60_000),
        RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(60),
        AUTH_RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(10),

        REQUEST_TIMEOUT_MS: z.coerce.number().int().min(1000).default(20_000),
    })
    .safeParse(process.env);




// Create Payload Validation Schema

export const CLAIM_LIMITS = Object.freeze({
    MAX_TOP_LEVEL_KEYS: 32,
    MAX_KEY_LENGTH: 64,
    MAX_STRING_LENGTH: 2048,
    MAX_ARRAY_LENGTH: 50,
    MAX_DEPTH: 5,
    MAX_SERIALIZED_BYTES: 8192,
});

export const CORRELATION_ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

export const claimKey = z
    .string()
    .max(CLAIM_LIMITS.MAX_KEY_LENGTH)
    .refine((k) => !FORBIDDEN_KEYS.includes(k), 'prototype-polluting keys are not allowed');

export const jsonValue = z.lazy(() =>
    z.union([
        z.string().max(CLAIM_LIMITS.MAX_STRING_LENGTH),
        z.number().finite(),
        z.boolean(),
        z.null(),
        z.array(jsonValue).max(CLAIM_LIMITS.MAX_ARRAY_LENGTH),
        z.record(claimKey, jsonValue),
    ]),
);


const bindingValue = z.string().trim().min(1).max(256).optional();

function structureDepth(node, depth = 1) {
    if (node === null || typeof node !== 'object') return depth;
    const children = Array.isArray(node) ? node : Object.values(node);
    if (children.length === 0) return depth;
    return children.reduce((max, child) => Math.max(max, structureDepth(child, depth + 1)), depth);
}

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

export function jwtCreateSchema(maxExpiry) {
    return withAliases(
        z
            .object({
                subject: bindingValue,
                audience: bindingValue,
                expectedSubject: bindingValue,
                expectedAudience: bindingValue,

                claims: z
                    .record(claimKey, jsonValue)
                    .refine(
                        (c) => Object.keys(c).length <= CLAIM_LIMITS.MAX_TOP_LEVEL_KEYS,
                        {
                            message: `At most ${CLAIM_LIMITS.MAX_TOP_LEVEL_KEYS} top-level custom claims`,
                        },
                    )
                    .refine(
                        (c) => !Object.keys(c).some((k) => PROTECTED_CLAIMS.includes(k)),
                        {
                            message: `These claims are set by the issuer and cannot be supplied: ${PROTECTED_CLAIMS.join(', ')}`,
                        },
                    )
                    .refine(
                        (c) => structureDepth(c) <= CLAIM_LIMITS.MAX_DEPTH,
                        {
                            message: `Claims may nest at most ${CLAIM_LIMITS.MAX_DEPTH} levels deep`,
                        },
                    )
                    .refine(
                        (c) =>
                            Buffer.byteLength(JSON.stringify(c), 'utf8') <=
                            CLAIM_LIMITS.MAX_SERIALIZED_BYTES,
                        {
                            message: `Serialized claims must not exceed ${CLAIM_LIMITS.MAX_SERIALIZED_BYTES} bytes`,
                        },
                    )
                    .optional(),

                data: z.any().optional(),

                expiresIn: z.coerce
                    .number()
                    .int()
                    .min(60, 'expiresIn must be at least 60 seconds')
                    .max(
                        maxExpiry,
                        `expiresIn must not exceed ${maxExpiry} seconds`,
                    )
                    .optional(),

                notBefore: z.coerce
                    .number()
                    .int()
                    .min(0)
                    .max(maxExpiry)
                    .optional(),
            })
            .strict(),
        [
            ['subject', 'expectedSubject'],
            ['audience', 'expectedAudience'],
        ],
    );

}

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