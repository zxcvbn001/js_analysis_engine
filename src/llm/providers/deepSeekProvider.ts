import type { LLMProvider, LLMSecretBatchResult, LLMSecretResult, SecretContext } from '../../types/llm.js';
import { getConfig } from '../../config/appConfig.js';
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
    const content = await this.completeJson(buildSecretPrompt(input));
    return normalizeLLMResult(JSON.parse(content));
  }

  async analyzeSecretsBatch(input: SecretContext[]): Promise<LLMSecretBatchResult[]> {
    const content = await this.completeJson(buildSecretBatchPrompt(input));
    const payload = JSON.parse(content) as { results?: unknown[] };
    return (payload.results ?? []).map(normalizeLLMBatchResult);
  }

  private async completeJson(prompt: string): Promise<string> {
    if (!this.options.apiKey) {
      throw new Error('LLM_API_KEY is not configured');
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);

    try {
      const response = await fetch(`${this.options.baseUrl.replace(/\/$/, '')}/chat/completions`, {
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

      if (!response.ok) {
        throw new Error(`DeepSeek request failed with ${response.status}`);
      }

      const payload = (await response.json()) as { choices?: Array<{ message?: { content?: string } }> };
      const content = payload.choices?.[0]?.message?.content;
      if (!content) {
        throw new Error('DeepSeek returned an empty response');
      }

      return content;
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
