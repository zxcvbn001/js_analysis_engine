import type { LLMProvider, LLMSecretBatchResult, LLMSecretResult, SecretContext } from '../../types/llm.js';
import { getConfig } from '../../config/appConfig.js';
import { errorFields, logError, logInfo } from '../../utils/logger.js';
import { buildSecretBatchPrompt, buildSecretPrompt } from '../prompts/secretPrompt.js';

export interface DeepSeekProviderOptions {
  apiKey: string;
  baseUrl: string;
  model: string;
  timeoutMs: number;
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

  private async completeJson(prompt: string, meta: { operation: string; candidateCount: number; candidateIds: string[] }): Promise<string> {
    if (!this.options.apiKey) {
      logError('llm_provider_request_blocked', {
        provider: 'deepseek',
        model: this.options.model,
        operation: meta.operation,
        reason: 'LLM_API_KEY is not configured',
      });
      throw new Error('LLM_API_KEY is not configured');
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);
    const url = `${this.options.baseUrl.replace(/\/$/, '')}/chat/completions`;
    const startedAt = Date.now();

    try {
      logInfo('llm_provider_request_start', {
        provider: 'deepseek',
        model: this.options.model,
        baseUrl: this.options.baseUrl,
        url,
        operation: meta.operation,
        candidateCount: meta.candidateCount,
        candidateIds: meta.candidateIds,
        promptLength: prompt.length,
        timeoutMs: this.options.timeoutMs,
      });

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.options.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: this.options.model,
          temperature: 0,
          response_format: { type: 'json_object' },
          messages: [{ role: 'user', content: prompt }],
        }),
        signal: controller.signal,
      });

      logInfo('llm_provider_response_received', {
        provider: 'deepseek',
        model: this.options.model,
        operation: meta.operation,
        status: response.status,
        ok: response.ok,
        durationMs: Date.now() - startedAt,
      });

      if (!response.ok) {
        throw new Error(`DeepSeek request failed with ${response.status}`);
      }

      const payload = (await response.json()) as { choices?: Array<{ message?: { content?: string } }> };
      const content = payload.choices?.[0]?.message?.content;
      if (!content) {
        throw new Error('DeepSeek returned an empty response');
      }

      logInfo('llm_provider_response_parsed', {
        provider: 'deepseek',
        model: this.options.model,
        operation: meta.operation,
        contentLength: content.length,
        durationMs: Date.now() - startedAt,
      });

      return content;
    } catch (error) {
      logError('llm_provider_request_failed', {
        provider: 'deepseek',
        model: this.options.model,
        operation: meta.operation,
        durationMs: Date.now() - startedAt,
        ...errorFields(error),
      });
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }
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
