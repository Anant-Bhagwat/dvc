import express, { Router } from 'express';
import rateLimit from 'express-rate-limit';

import {
    env,
    jwtCreate,
} from '../config/jwtkeys.config.js';



import {
    createJwt,
    verifyJwt,
} from '../services/jwt.js';

import {
    noStore,
    requireJsonBody,
} from '../middleware/request.js';

import {
    requireAuth,
} from '../middleware/auth.js';

import {
    validateBody,
} from '../middleware/validation.js';
import { jwtCreateSchema, jwtVerifySchema } from '../validations/jwt.validation.js';

const router = Router();

const authLimiter = rateLimit({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    max: env.AUTH_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    requestWasSuccessful: (_req, res) => res.statusCode !== 401,
    message: {
        status: 'error',
        error: {
            code: 'TOO_MANY_FAILED_AUTH',
            message: 'Too many failed authentication attempts',
        },
    },
});

const asyncHandler = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

const createToken = asyncHandler(async (req, res) => {
    const {
        subject,
        audience,
        claims,
        data,
        expiresIn,
        notBefore,
    } = req.body;


    const result = await createJwt({
        subject,
        audience,
        claims,
        data,
        expiresIn,
        notBefore,
    });

    res.status(201).json({
        status: 'success',
        data: {
            token: result.token,
            token_id: result.jwtId,
            issued_at: new Date(
                result.issuedAt * 1000,
            ).toISOString(),
            expires_at: new Date(
                result.expiresAt * 1000,
            ).toISOString(),
            token_type: 'Bearer',
            expires_in: result.expiresAt - result.issuedAt,
        },
        correlationId: req.correlationId,
    });
});

const verifyToken = asyncHandler(async (req, res) => {
    const {
        token,
        expectedAudience,
        expectedSubject,
    } = req.body;

    const result = await verifyJwt(token, {
        expectedAudience,
        expectedSubject,
    });

    const {
        iss,
        sub,
        aud,
        exp,
        nbf,
        iat,
        jti,
        ...custom
    } = result.payload;

    const dataClaim = env.JWT_DATA_CLAIM;

    const hasData = Object.hasOwn(custom, dataClaim);

    const data = hasData
        ? custom[dataClaim]
        : null;

    if (hasData) {
        delete custom[dataClaim];
    }

    res.status(200).json({
        status: 'success',
        data: {
            valid: true,

            header: {
                alg: result.header.alg,
                typ: result.header.typ,
                kid: result.header.kid,
            },

            issuer: iss,
            subject: sub ?? null,
            audience: aud ?? null,
            token_id: jti ?? null,

            issued_at: new Date(
                iat * 1000,
            ).toISOString(),

            expires_at: new Date(
                exp * 1000,
            ).toISOString(),

            not_before:
                typeof nbf === 'number'
                    ? new Date(nbf * 1000).toISOString()
                    : null,

            claims: custom,
            data,
        },

        correlationId: req.correlationId,
    });


});

router.use(
    noStore,
    authLimiter,
    requireAuth,
    requireJsonBody,
    // Body parser belongs before validateBody.
);

router.use(
    express.json({
        limit: env.JSON_BODY_LIMIT,
        strict: true,
        type: 'application/json',
    }),
);

router.post(
    '/create',
    validateBody(jwtCreate),
    createToken,
);

router.post(
    '/verify',
    validateBody(jwtVerifySchema),
    verifyToken,
);


export default router;
