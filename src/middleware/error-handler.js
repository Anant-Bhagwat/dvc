import {
    AppError,
} from '../services/jwt.js';

import {
    logger,
} from '../config/jwtkeys.config.js';

export function notFoundHandler(req, res) {
    res.status(404).json({
        status: 'error',
        error: {
            code: 'ROUTE_NOT_FOUND',
            message: `No route matches ${req.method} ${req.path}`,
        },
        correlationId: req.correlationId,
    });
}

// eslint-disable-next-line no-unused-vars -- Express identifies error handlers by arity
export function errorHandler(err, req, res, _next) {
    const correlationId = req.correlationId;
    if (err instanceof SyntaxError && 'body' in err) {
        return res.status(400).json({
            status: 'error',
            error: {
                code: 'MALFORMED_JSON',
                message: 'Request body is not valid JSON',
            },
            correlationId,
        });
    }

    if (err?.type === 'entity.too.large') {
        return res.status(413).json({
            status: 'error',
            error: {
                code: 'PAYLOAD_TOO_LARGE',
                message:
                    'Request body exceeds the configured limit',
            },
            correlationId,
        });
    }

    if (err instanceof AppError) {
        logger[
            err.httpStatus >= 500
                ? 'error'
                : 'warn'
        ](
            {
                correlationId,
                code: err.code,
                httpStatus: err.httpStatus,
                path: req.path,
                err:
                    err.httpStatus >= 500
                        ? err.message
                        : undefined,
            },
            'Request failed',
        );

        return res.status(err.httpStatus).json({
            status: 'error',
            error: {
                code: err.code,
                message: err.expose
                    ? err.message
                    : 'An internal error occurred',

                ...(err.expose && err.details
                    ? { details: err.details }
                    : {}),
            },
            correlationId,
        });
    }

    logger.error(
        {
            correlationId,
            err: err?.message,
            stack: err?.stack,
            path: req.path,
        },
        'Unhandled error',
    );

    return res.status(500).json({
        status: 'error',
        error: {
            code: 'INTERNAL_ERROR',
            message: 'An internal error occurred',
        },
        correlationId,
    });


}
