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
import { summarizeAnalyzeRequest, summarizeApiResponse, summarizeContent } from '../../utils/analysisSummary.js';
import { errorFields, logError, logInfo } from '../../utils/logger.js';
import { formatAnalysisResponse } from '../response/analysisResponseFormatter.js';

const llmAnalyzer = new LLMSecretAnalyzer(createLLMProvider());

export async function analyzeJsController(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const parsed = analyzeJsRequestSchema.safeParse(request.body);
  if (!parsed.success) {
    reply.code(400).send({ success: false, error: { message: parsed.error.message } });
    return;
  }

  const mode = parsed.data.fast_mode === true ? 'fast' : parsed.data.mode ?? 'full';
  const responseMode = parsed.data.response_mode ?? 'full';
  const requestSummary = summarizeAnalyzeRequest({
    url: parsed.data.url,
    content: parsed.data.content,
    async: parsed.data.async,
    responseMode,
    fastMode: parsed.data.fast_mode,
    requestedMode: parsed.data.mode,
    mode,
  });
  logInfo('analyze_js_request_received', {
    url: parsed.data.url,
    ...requestSummary,
  });
  logInfo('analyze_js_request_summary', {
    url: parsed.data.url,
    ...requestSummary,
  });
  if (parsed.data.async === true) {
    const task = submitAnalysisTask({
      url: parsed.data.url,
      content: parsed.data.content,
      mode,
      responseMode,
    });
    const response = {
      success: true,
      task_id: task.id,
      status: task.status,
      status_url: `/analyze/tasks/${task.id}`,
    };
    logInfo('analyze_js_task_submitted', {
      url: parsed.data.url,
      taskId: task.id,
      returnedTaskId: response.task_id,
      status: response.status,
      statusUrl: response.status_url,
      ...requestSummary,
    });
    reply.code(202).send(response);
    return;
  }

  let content: string;
  let source: 'content' | 'download';
  try {
    if (parsed.data.content?.trim()) {
      content = parsed.data.content;
      source = 'content';
    } else {
      content = await fetchTextContent(parsed.data.url ?? '', getConfig().fetch);
      source = 'download';
    }
    logInfo('analyze_js_content_prepared', {
      url: parsed.data.url,
      ...summarizeContent({ content, source, url: parsed.data.url }),
    });
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
  const response = formatAnalysisResponse(result, responseMode);
  logInfo('analyze_js_response_sent', {
    url: parsed.data.url,
    responseMode,
    ...summarizeApiResponse(response),
  });
  reply.send(response);
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
  logInfo('analyze_task_response_sent', {
    taskId,
    status: task.status,
    hasResult: Boolean(task.result),
    hasError: Boolean(task.error),
    resultSummary: task.result ? summarizeApiResponse(task.result) : undefined,
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
