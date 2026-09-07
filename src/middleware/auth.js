import crypto from 'node:crypto';

import {
    UnauthorizedError,
} from '../services/jwt.js';

import {
    env,
    logger,
} from '../config/jwtkeys.config.js';

const digest = (value) =>
    crypto.createHash('sha256').update(value, 'utf8').digest();

function tokenMatches(presented) {
    const presentedDigest = digest(presented);

    let matched = false;

    for (const configured of env.API_ACCESS_TOKENS) {
        if (crypto.timingSafeEqual(presentedDigest, digest(configured))) {
            matched = true;
        }
    }

    return matched;

}

export function requireAuth(req, _res, next) {
    if (!env.AUTH_ENABLED) {
        req.auth = {
            subject: 'anonymous',
            authenticated: false,
        };

        return next();
    }

    const header = req.get('authorization') ?? '';
    const [scheme, ...rest] = header.split(' ');

    const token = /^Bearer$/i.test(scheme)
        ? rest.join(' ').trim()
        : '';

    if (!token) {
        return next(
            new UnauthorizedError(
                'Missing or malformed Authorization header',
            ),
        );
    }

    if (!tokenMatches(token)) {
        logger.warn(
            {
                ip: req.ip,
                path: req.path,
                correlationId: req.correlationId,
            },
            'Rejected request with invalid access token',
        );

        return next(
            new UnauthorizedError('Invalid access token'),
        );
    }

    req.auth = {
        subject: 'api-client',
        authenticated: true,
    };

    return next();

}