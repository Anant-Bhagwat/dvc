import { ValidationError } from '../services/jwt.js';

export function validateBody(schema) {
  return (req, _res, next) => {
    const result = schema.safeParse(req.body ?? {});

    if (!result.success) {
      const details = result.error.issues.map((issue) => ({
        field: issue.path.join('.') || '(body)',
        message: issue.message,
      }));

      return next(
        new ValidationError(
          'Request validation failed',
          details,
        ),
      );
    }

    req.body = result.data;

    return next();
  };

}