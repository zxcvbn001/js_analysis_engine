import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { errorFields, logError } from '../../utils/logger.js';

export function errorHandler(error: FastifyError, request: FastifyRequest, reply: FastifyReply): void {
  logError('http_request_error', {
    method: request.method,
    url: request.url,
    statusCode: error.statusCode ?? 500,
    ...errorFields(error),
  });
  reply.code(error.statusCode ?? 500).send({
    success: false,
    error: {
      message: error.message,
    },
  });
}
