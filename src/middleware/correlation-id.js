import crypto from 'node:crypto';

import { CORRELATION_ID_RE } from '../validations/jwt.validation.js';

export function correlationId(req, res, next) {
    const supplied = req.get('x-correlation-id');

    req.correlationId = CORRELATION_ID_RE.test(supplied ?? '')
        ? supplied
        : crypto.randomUUID();

    res.set('x-correlation-id', req.correlationId);

    next();

}