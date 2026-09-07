import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import {
  env,
} from './config/jwtkeys.config.js';

import {
  correlationId,
} from './middleware/correlation-id.js';

import {
  notFoundHandler,
  errorHandler,
} from './middleware/error-handler.js';

import jwtRoutes from './routes/jwt.routes.js';

export function createApp() {
  const app = express();

  app.set('trust proxy', env.TRUST_PROXY);
  app.set('query parser', 'simple');
  app.set('etag', false);

  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"],
        },
      },

      hsts:
        env.NODE_ENV === 'production'
          ? {
            maxAge: 31_536_000,
            includeSubDomains: true,
          }
          : false,

      referrerPolicy: {
        policy: 'no-referrer',
      },

      crossOriginResourcePolicy: {
        policy: 'same-origin',
      },
    }),
  );

  app.use(correlationId);

  const limitMessage = (code, message) => ({
    status: 'error',
    error: {
      code,
      message,
    },
  });

  app.use(
    '/api/',
    rateLimit({
      windowMs: env.RATE_LIMIT_WINDOW_MS,
      max: env.RATE_LIMIT_MAX,
      standardHeaders: true,
      legacyHeaders: false,

      message: limitMessage(
        'RATE_LIMITED',
        'Too many requests',
      ),
    }),
  );

  app.use(
    '/api/v1/jwt',
    jwtRoutes,
  );

  app.get('/health', (_req, res) => {
    res.status(200).json({
      status: 'success',
      data: {
        service: 'jwt-api',
        uptime: process.uptime(),
      },
    });
  });

  app.use(notFoundHandler);

  app.use(errorHandler);

  return app;


}

export default createApp;
