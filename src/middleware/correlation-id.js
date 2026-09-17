import crypto from 'node:crypto';

const CORRELATION_ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

export function correlationId(req, res, next) {
    const supplied = req.get('x-correlation-id');

    req.correlationId = CORRELATION_ID_RE.test(supplied ?? '')
        ? supplied
        : crypto.randomUUID();

    res.set('x-correlation-id', req.correlationId);

    next();

}