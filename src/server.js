import { env, logger, initKeys } from './config.js';
import { createApp } from './app.js';

async function bootstrap() {
  await initKeys();

  const server = createApp().listen(env.PORT, () => {
    logger.info({ port: env.PORT, env: env.NODE_ENV, issuer: env.JWT_ISSUER }, 'JWT API listening');
  });

  server.requestTimeout = env.REQUEST_TIMEOUT_MS;
  server.headersTimeout = Math.min(env.REQUEST_TIMEOUT_MS, 15_000);
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;

  const shutdown = (signal) => {
    logger.info({ signal }, 'Shutting down');

    setTimeout(() => {
      logger.error('Graceful shutdown timed out; forcing exit');
      process.exit(1);
    }, 10_000).unref();

    server.close(() => {
      logger.info('Shutdown complete');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => {
    logger.fatal({ reason: reason?.message ?? String(reason) }, 'Unhandled rejection');
    process.exit(1);
  });

  process.on('uncaughtException', (err) => {
    logger.fatal({ err: err.message, stack: err.stack }, 'Uncaught exception');
    process.exit(1);
  });
}

bootstrap().catch((err) => {
  logger.fatal({ err: err.message, stack: err.stack }, 'Failed to start service');
  process.exit(1);
});
