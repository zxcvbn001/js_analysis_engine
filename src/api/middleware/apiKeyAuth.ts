import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AppConfig } from '../../config/appConfig.js';

export function createApiKeyAuth(config: AppConfig) {
  const allowedKeys = new Set(config.auth.apiKeys);
  const headerName = config.auth.headerName.toLowerCase();

  return async function apiKeyAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    if (!config.auth.enabled || request.url === '/health') {
      return;
    }

    const headerValue = request.headers[headerName];
    const apiKey = Array.isArray(headerValue) ? headerValue[0] : headerValue;

    if (!apiKey || !allowedKeys.has(apiKey)) {
      reply.code(401).send({
        success: false,
        error: {
          message: 'Missing or invalid API key',
        },
      });
    }
  };
}
