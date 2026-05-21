import type { FastifyReply, FastifyRequest } from 'fastify';
import { LLMSecretAnalyzer } from '../../llm/analyzers/llmSecretAnalyzer.js';
import { createLLMProvider } from '../../llm/providers/providerFactory.js';
import type { SecretCandidate, SecretContext } from '../../types/llm.js';
import { analyzeJavaScript } from '../../engine/analyzers/javascriptAnalyzer.js';
import { analyzeJsRequestSchema, analyzeSecretRequestSchema } from '../schemas/analyzeSchemas.js';
import { sha256 } from '../../utils/hash.js';
import { fetchTextContent } from '../../utils/fetchContent.js';
import { getConfig } from '../../config/appConfig.js';
import { getAnalysisTask, submitAnalysisTask } from '../../engine/analyzers/analysisTaskStore.js';
import { errorFields, logError } from '../../utils/logger.js';

const llmAnalyzer = new LLMSecretAnalyzer(createLLMProvider());

export async function analyzeJsController(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const parsed = analyzeJsRequestSchema.safeParse(request.body);
  if (!parsed.success) {
    reply.code(400).send({ success: false, error: { message: parsed.error.message } });
    return;
  }

  const mode = parsed.data.fast_mode === true ? 'fast' : parsed.data.mode ?? 'full';
  if (parsed.data.async === true) {
    const task = submitAnalysisTask({
      url: parsed.data.url,
      content: parsed.data.content,
      mode,
    });
    reply.code(202).send({
      success: true,
      task_id: task.id,
      status: task.status,
      status_url: `/analyze/tasks/${task.id}`,
    });
    return;
  }

  let content: string;
  try {
    content = parsed.data.content?.trim()
      ? parsed.data.content
      : await fetchTextContent(parsed.data.url ?? '', getConfig().fetch);
  } catch (error) {
    logError('analyze_js_prepare_failed', {
      url: parsed.data.url,
      ...errorFields(error),
    });
    reply.code(502).send({
      success: false,
      error: {
        message: error instanceof Error ? error.message : 'Failed to prepare JavaScript content',
      },
    });
    return;
  }
  const result = await analyzeJavaScript({ url: parsed.data.url, content, mode });
  reply.send(result);
}

export async function getAnalyzeTaskController(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const taskId = (request.params as { id?: string }).id;
  if (!taskId) {
    reply.code(400).send({ success: false, error: { message: 'Task id is required' } });
    return;
  }

  const task = getAnalysisTask(taskId);
  if (!task) {
    reply.code(404).send({ success: false, error: { message: 'Task not found' } });
    return;
  }

  reply.send({
    success: true,
    task,
  });
}

export async function analyzeSecretController(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const parsed = analyzeSecretRequestSchema.safeParse(request.body);
  if (!parsed.success) {
    reply.code(400).send({ success: false, error: { message: parsed.error.message } });
    return;
  }

  const candidate: SecretCandidate = {
    id: sha256(parsed.data.candidate),
    type: 'candidate',
    value: parsed.data.candidate,
    severity: 'medium',
    evidence: parsed.data.candidate,
  };
  const context: SecretContext = {
    candidate,
    context: parsed.data.context.slice(0, 12000),
    nearbyApis: [],
    nearbyHeaders: [],
  };

  try {
    const result = await llmAnalyzer.analyzeNow(context);
    reply.send(
      result
        ? {
            is_secret: result.is_secret,
            type: result.secret_type,
            severity: result.severity,
            confidence: result.confidence,
            reason: result.reason,
          }
        : {
            is_secret: false,
            type: 'unknown',
            severity: 'low',
            confidence: 0,
            reason: 'LLM provider is not configured',
          },
    );
  } catch (error) {
    reply.send({
      is_secret: false,
      type: 'unknown',
      severity: 'low',
      confidence: 0,
      reason: error instanceof Error ? error.message : 'LLM analysis failed',
    });
  }
}
