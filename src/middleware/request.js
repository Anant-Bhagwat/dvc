import { AppError } from '../services/jwt.js';

export function noStore(_req, res, next) {
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');

    next();

}

export function requireJsonBody(req, _res, next) {
    if (!req.is('application/json')) {
        return next(
            new AppError(
                'Content-Type must be application/json',
                {
                    code: 'UNSUPPORTED_MEDIA_TYPE',
                    httpStatus: 415,
                },
            ),
        );
    }

    return next();

}