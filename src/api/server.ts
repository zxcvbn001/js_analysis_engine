import Fastify from 'fastify';
import { registerAnalyzeRoutes } from './routes/analyzeRoutes.js';
import { errorHandler } from './middleware/errorHandler.js';
import { getConfig, type AppConfig } from '../config/appConfig.js';
import { createApiKeyAuth } from './middleware/apiKeyAuth.js';
import { configureFileLogger, createPinoConsoleStream } from '../utils/logger.js';

export async function buildServer(config: AppConfig = getConfig()) {
  configureFileLogger(config.logging);
  const app = Fastify({
    logger: config.server.logLevel === 'silent'
      ? false
      : {
          level: config.server.logLevel,
          stream: createPinoConsoleStream(),
        },
    bodyLimit: config.server.bodyLimitMb * 1024 * 1024,
  });

  app.setErrorHandler(errorHandler);
  app.addHook('preHandler', createApiKeyAuth(config));

  app.get('/health', async () => ({ success: true }));
  await registerAnalyzeRoutes(app);

  return app;
}
