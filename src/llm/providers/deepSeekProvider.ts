import type { FindingReviewContext, LLMFindingReviewResult, LLMProvider, LLMSecretBatchResult, LLMSecretResult, LLMUnifiedReviewResult, SecretContext, UnifiedReviewContext } from '../../types/llm.js';
import { getConfig } from '../../config/appConfig.js';
import { errorFields, logError, logInfo, logWarn } from '../../utils/logger.js';
import { buildFindingBatchPrompt, buildSecretBatchPrompt, buildSecretPrompt, buildUnifiedReviewPrompt, toCompactUnifiedPromptPayload } from '../prompts/secretPrompt.js';

const MAX_LLM_PROVIDER_ATTEMPTS = 2;
const LLM_RETRY_DELAY_MS = 500;

export interface DeepSeekProviderOptions {
  apiKey: string;
  baseUrl: string;
  model: string;
  timeoutMs: number;
  logPrompts: boolean;
  logResponses: boolean;
  logRawPayloads: boolean;
}

export class DeepSeekProvider implements LLMProvider {
  private readonly options: DeepSeekProviderOptions;

  constructor(options?: Partial<DeepSeekProviderOptions>) {
    const config = getConfig();
    this.options = {
      apiKey: options?.apiKey ?? config.llm.apiKey,
      baseUrl: options?.baseUrl ?? config.llm.baseUrl,
      model: options?.model ?? config.llm.model,
      timeoutMs: options?.timeoutMs ?? config.llm.timeoutMs,
      logPrompts: options?.logPrompts ?? config.llm.logPrompts,
      logResponses: options?.logResponses ?? config.llm.logResponses,
      logRawPayloads: options?.logRawPayloads ?? config.llm.logRawPayloads,
    };
  }

  async analyzeSecret(input: SecretContext): Promise<LLMSecretResult> {
    const content = await this.completeJson(buildSecretPrompt(input), {
      operation: 'secret-single',
      candidateCount: 1,
      candidateIds: [input.candidate.id],
    });
    return normalizeLLMResult(JSON.parse(content));
  }

  async analyzeSecretsBatch(input: SecretContext[]): Promise<LLMSecretBatchResult[]> {
    const content = await this.completeJson(buildSecretBatchPrompt(input), {
      operation: 'secret-batch',
      candidateCount: input.length,
      candidateIds: input.map((context) => context.candidate.id),
    });
    const payload = JSON.parse(content) as { results?: unknown[] };
    return (payload.results ?? []).map(normalizeLLMBatchResult);
  }

  async analyzeFindingsBatch(input: FindingReviewContext[]): Promise<LLMFindingReviewResult[]> {
    const content = await this.completeJson(buildFindingBatchPrompt(input), {
      operation: 'finding-batch',
      candidateCount: input.length,
      candidateIds: input.map((context) => context.id),
    });
    const payload = JSON.parse(content) as { results?: unknown[] };
    return (payload.results ?? []).map(normalizeLLMFindingResult);
  }

  async analyzeUnifiedBatch(input: UnifiedReviewContext): Promise<LLMUnifiedReviewResult> {
    const promptPayload = toCompactUnifiedPromptPayload(input);
    const content = await this.completeJson(buildUnifiedReviewPrompt(input), {
      operation: 'unified-batch',
      candidateCount: input.secrets.length + input.findings.length,
      candidateIds: [
        ...input.secrets.map((context) => context.candidate.id),
        ...input.findings.map((context) => context.id),
      ],
      promptStats: {
        apiCount: input.apis.length,
        secretCount: input.secrets.length,
        findingCount: input.findings.length,
        apiChars: JSON.stringify(promptPayload.apis ?? []).length,
        secretValueChars: input.secrets.reduce((total, context) => total + context.candidate.value.length, 0),
        secretEvidenceChars: JSON.stringify(promptPayload.secrets ?? []).length,
        findingValueChars: input.findings.reduce((total, context) => total + (context.finding.value?.length ?? 0), 0),
        findingEvidenceChars: JSON.stringify(promptPayload.findings ?? []).length,
      },
    });
    const payload = JSON.parse(content) as { secrets?: unknown[]; findings?: unknown[] };
    return {
      secrets: (payload.secrets ?? []).map(normalizeLLMBatchResult),
      findings: (payload.findings ?? []).map(normalizeLLMFindingResult),
    };
  }

  private async completeJson(prompt: string, meta: { operation: string; candidateCount: number; candidateIds: string[]; promptStats?: Record<string, number> }): Promise<string> {
    if (!this.options.apiKey) {
      logError('llm_provider_request_blocked', {
        provider: 'deepseek',
        model: this.options.model,
        operation: meta.operation,
        reason: 'LLM_API_KEY is not configured',
      });
      throw new Error('LLM_API_KEY is not configured');
    }

    const url = `${this.options.baseUrl.replace(/\/$/, '')}/chat/completions`;
    const startedAt = Date.now();
    const requestBody = {
      model: this.options.model,
      temperature: 0,
      response_format: { type: 'json_object' },
      messages: [{ role: 'user', content: prompt }],
    };

    logInfo('llm_provider_prompt_built', {
      provider: 'deepseek',
      model: this.options.model,
      operation: meta.operation,
      candidateCount: meta.candidateCount,
      candidateIds: meta.candidateIds,
      promptLength: prompt.length,
      promptStats: meta.promptStats,
      promptPreview: this.options.logPrompts ? redactLLMText(prompt) : undefined,
      promptRaw: this.options.logPrompts && this.options.logRawPayloads ? prompt : undefined,
    });

    logInfo('llm_provider_request_start', {
      provider: 'deepseek',
      model: this.options.model,
      baseUrl: this.options.baseUrl,
      url,
      operation: meta.operation,
      candidateCount: meta.candidateCount,
      candidateIds: meta.candidateIds,
      promptLength: prompt.length,
      promptStats: meta.promptStats,
      requestBodyLength: JSON.stringify(requestBody).length,
      requestBodyPreview: this.options.logPrompts ? redactLLMText(JSON.stringify(requestBody)) : undefined,
      requestBodyRaw: this.options.logPrompts && this.options.logRawPayloads ? requestBody : undefined,
      timeoutMs: this.options.timeoutMs,
      maxAttempts: MAX_LLM_PROVIDER_ATTEMPTS,
    });

    for (let attempt = 1; attempt <= MAX_LLM_PROVIDER_ATTEMPTS; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);
      const attemptStartedAt = Date.now();

      try {
        logInfo('llm_provider_request_attempt_start', {
          provider: 'deepseek',
          model: this.options.model,
          operation: meta.operation,
          attempt,
          maxAttempts: MAX_LLM_PROVIDER_ATTEMPTS,
          timeoutMs: this.options.timeoutMs,
        });

        const response = await fetch(url, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${this.options.apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestBody),
          signal: controller.signal,
        });

        logInfo('llm_provider_response_received', {
          provider: 'deepseek',
          model: this.options.model,
          operation: meta.operation,
          attempt,
          maxAttempts: MAX_LLM_PROVIDER_ATTEMPTS,
          status: response.status,
          ok: response.ok,
          durationMs: Date.now() - attemptStartedAt,
          totalDurationMs: Date.now() - startedAt,
        });

        if (!response.ok) {
          throw new DeepSeekHttpError(response.status, await safeResponsePreview(response));
        }

        const payload = (await response.json()) as { choices?: Array<{ message?: { content?: string } }> };
        logInfo('llm_provider_response_body_received', {
          provider: 'deepseek',
          model: this.options.model,
          operation: meta.operation,
          attempt,
          maxAttempts: MAX_LLM_PROVIDER_ATTEMPTS,
          choiceCount: payload.choices?.length ?? 0,
          durationMs: Date.now() - attemptStartedAt,
          totalDurationMs: Date.now() - startedAt,
          responsePreview: this.options.logResponses ? redactLLMText(JSON.stringify(payload)) : undefined,
          responseRaw: this.options.logResponses && this.options.logRawPayloads ? payload : undefined,
        });
        const content = payload.choices?.[0]?.message?.content;
        if (!content) {
          throw new Error('DeepSeek returned an empty response');
        }

        logInfo('llm_provider_response_parsed', {
          provider: 'deepseek',
          model: this.options.model,
          operation: meta.operation,
          attempt,
          maxAttempts: MAX_LLM_PROVIDER_ATTEMPTS,
          contentLength: content.length,
          contentPreview: this.options.logResponses ? redactLLMText(content) : undefined,
          contentRaw: this.options.logResponses && this.options.logRawPayloads ? content : undefined,
          durationMs: Date.now() - attemptStartedAt,
          totalDurationMs: Date.now() - startedAt,
        });

        return content;
      } catch (error) {
        const willRetry = attempt < MAX_LLM_PROVIDER_ATTEMPTS && isRetryableLLMError(error);
        if (willRetry) {
          logWarn('llm_provider_request_retry', {
            provider: 'deepseek',
            model: this.options.model,
            operation: meta.operation,
            attempt,
            maxAttempts: MAX_LLM_PROVIDER_ATTEMPTS,
            delayMs: LLM_RETRY_DELAY_MS,
            durationMs: Date.now() - attemptStartedAt,
            totalDurationMs: Date.now() - startedAt,
            ...errorFields(error),
            ...llmErrorExtraFields(error),
          });
          await delay(LLM_RETRY_DELAY_MS);
          continue;
        }

        logError('llm_provider_request_failed', {
          provider: 'deepseek',
          model: this.options.model,
          operation: meta.operation,
          attempt,
          maxAttempts: MAX_LLM_PROVIDER_ATTEMPTS,
          retryable: isRetryableLLMError(error),
          durationMs: Date.now() - startedAt,
          ...errorFields(error),
          ...llmErrorExtraFields(error),
        });
        throw error;
      } finally {
        clearTimeout(timeout);
      }
    }

    throw new Error('DeepSeek request failed after retry attempts');
  }
}

class DeepSeekHttpError extends Error {
  constructor(readonly status: number, readonly responsePreview: string) {
    super(`DeepSeek request failed with ${status}`);
    this.name = 'DeepSeekHttpError';
  }
}

async function safeResponsePreview(response: Response): Promise<string> {
  try {
    return redactLLMText((await response.text()).slice(0, 2000));
  } catch {
    return '';
  }
}

function isRetryableLLMError(error: unknown): boolean {
  if (error instanceof DeepSeekHttpError) {
    return error.status === 429 || error.status >= 500;
  }

  if (!(error instanceof Error)) {
    return false;
  }

  if (error.name === 'AbortError') {
    return false;
  }

  const cause = error.cause;
  const causeText = cause instanceof Error ? `${cause.name} ${cause.message}` : String(cause ?? '');
  const text = `${error.name} ${error.message} ${causeText}`.toLowerCase();
  return /fetch failed|network|socket|other side closed|connection|econnreset|etimedout|terminated/.test(text);
}

function llmErrorExtraFields(error: unknown): Record<string, unknown> {
  if (error instanceof DeepSeekHttpError) {
    return {
      httpStatus: error.status,
      responsePreview: error.responsePreview,
    };
  }
  return {};
}

async function delay(ms: number): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function redactLLMText(value: string, maxLength = 12000): string {
  const redacted = value
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, 'Bearer [REDACTED]')
    .replace(/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, '[AWS_KEY_REDACTED]')
    .replace(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[JWT_REDACTED]')
    .replace(/("(?:value|password|passwd|pwd|token|secret|apiKey|api_key|accessKey|access_key|secretKey|secret_key)"\s*:\s*")([^"]{1,500})(")/gi, '$1[REDACTED]$3')
    .replace(/((?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)\s*[=:]\s*["']?)([^"',\s}]{4,500})/gi, '$1[REDACTED]');

  return redacted.length > maxLength ? `${redacted.slice(0, maxLength)}... [truncated ${redacted.length - maxLength} chars]` : redacted;
}

export function normalizeLLMBatchResult(value: unknown): LLMSecretBatchResult {
  const raw = value as Partial<LLMSecretBatchResult> & { type?: string; secret_type?: string };
  return {
    id: String(raw.id ?? ''),
    ...normalizeLLMResult(value),
  };
}

export function normalizeLLMResult(value: unknown): LLMSecretResult {
  const raw = value as Partial<LLMSecretResult> & { type?: string; secret_type?: string };
  return {
    is_secret: Boolean(raw.is_secret),
    secret_type: String(raw.secret_type ?? raw.type ?? 'unknown'),
    severity: raw.severity === 'low' || raw.severity === 'medium' || raw.severity === 'high' ? raw.severity : 'medium',
    confidence: typeof raw.confidence === 'number' ? Math.max(0, Math.min(1, raw.confidence)) : 0.5,
    reason: String(raw.reason ?? ''),
  };
}

export function normalizeLLMFindingResult(value: unknown): LLMFindingReviewResult {
  const raw = value as Partial<LLMFindingReviewResult>;
  return {
    id: String(raw.id ?? ''),
    is_risk: Boolean(raw.is_risk),
    category: String(raw.category ?? ''),
    type: String(raw.type ?? ''),
    severity: raw.severity === 'low' || raw.severity === 'medium' || raw.severity === 'high' ? raw.severity : 'medium',
    confidence: typeof raw.confidence === 'number' ? Math.max(0, Math.min(1, raw.confidence)) : 0.5,
    reason: String(raw.reason ?? ''),
  };
}
