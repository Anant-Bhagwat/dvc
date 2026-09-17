import { z } from 'zod';

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

        JSON_BODY_LIMIT: z.string().default('1mb'),

        RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).default(60_000),
        RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(60),

        REQUEST_TIMEOUT_MS: z.coerce.number().int().min(1000).default(20_000),
    })
    .safeParse(process.env);
