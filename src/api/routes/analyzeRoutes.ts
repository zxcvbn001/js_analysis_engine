import type { FastifyInstance } from 'fastify';
import { analyzeJsController, analyzeSecretController, getAnalyzeTaskController } from '../controllers/analyzeController.js';

export async function registerAnalyzeRoutes(app: FastifyInstance): Promise<void> {
  app.post('/analyze/js', analyzeJsController);
  app.get('/analyze/tasks/:id', getAnalyzeTaskController);
  app.post('/analyze/secret', analyzeSecretController);
}
