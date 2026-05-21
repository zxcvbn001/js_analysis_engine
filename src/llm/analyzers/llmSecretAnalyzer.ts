import type { LLMProvider, LLMSecretBatchResult, LLMSecretResult, SecretContext } from '../../types/llm.js';
import type { SecretResult } from '../../types/results.js';
import { sha256 } from '../../utils/hash.js';
import { SecretAnalysisCache } from './secretCache.js';
import { AsyncTaskQueue } from './secretQueue.js';

export class LLMSecretAnalyzer {
  private readonly cache: SecretAnalysisCache;
  private readonly queue: AsyncTaskQueue;

  constructor(private readonly provider?: LLMProvider, cache?: SecretAnalysisCache, queue?: AsyncTaskQueue) {
    this.cache = cache ?? new SecretAnalysisCache();
    this.queue = queue ?? new AsyncTaskQueue(1, 1000);
  }

  async analyzeNow(context: SecretContext): Promise<LLMSecretResult | undefined> {
    if (!this.provider) {
      return undefined;
    }

    const key = cacheKey(context);
    const cached = this.cache.get(key);
    if (cached) {
      return cached;
    }

    const result = await this.provider.analyzeSecret(context);
    this.cache.set(key, result);
    return result;
  }

  async analyzeBatch(contexts: SecretContext[]): Promise<LLMSecretBatchResult[]> {
    if (!this.provider || contexts.length === 0) {
      return [];
    }

    if (this.provider.analyzeSecretsBatch) {
      return this.provider.analyzeSecretsBatch(contexts);
    }

    const results: LLMSecretBatchResult[] = [];
    for (const context of contexts) {
      const result = await this.analyzeNow(context);
      if (result) {
        results.push({
          id: context.candidate.id,
          ...result,
        });
      }
    }
    return results;
  }

  isEnabled(): boolean {
    return Boolean(this.provider);
  }

  enqueue(context: SecretContext): boolean {
    if (!this.provider) {
      return false;
    }

    return this.queue.enqueue(async () => {
      await this.analyzeNow(context);
    });
  }

  toSecretResult(fallback: SecretResult, llm?: LLMSecretResult): SecretResult {
    if (!llm || !llm.is_secret) {
      return fallback;
    }

    return {
      ...fallback,
      type: llm.secret_type,
      severity: llm.severity,
      confidence: llm.confidence,
      source: 'llm+regex',
      evidence: llm.reason || fallback.evidence,
    };
  }
}

function cacheKey(context: SecretContext): string {
  return sha256(`${context.candidate.value}\n${context.context}`);
}
