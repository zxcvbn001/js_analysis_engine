import type { LLMProvider, LLMSecretBatchResult, LLMSecretResult, SecretContext } from '../../types/llm.js';
import type { SecretResult } from '../../types/results.js';
import { sha256 } from '../../utils/hash.js';
import { errorFields, logError, logInfo } from '../../utils/logger.js';
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
      logInfo('llm_secret_analyze_skipped', {
        candidateId: context.candidate.id,
        candidateType: context.candidate.type,
        reason: 'provider is not configured',
      });
      return undefined;
    }

    const key = cacheKey(context);
    const cached = this.cache.get(key);
    if (cached) {
      logInfo('llm_secret_cache_hit', {
        candidateId: context.candidate.id,
        candidateType: context.candidate.type,
        cacheKey: key,
        isSecret: cached.is_secret,
        secretType: cached.secret_type,
        severity: cached.severity,
        confidence: cached.confidence,
      });
      return cached;
    }

    logInfo('llm_secret_call_start', {
      candidateId: context.candidate.id,
      candidateType: context.candidate.type,
      candidateSeverity: context.candidate.severity,
      valueLength: context.candidate.value.length,
      valueHash: context.candidate.id,
      contextLength: context.context.length,
      nearbyApiCount: context.nearbyApis.length,
      cacheKey: key,
    });
    const startedAt = Date.now();
    try {
      const result = await this.provider.analyzeSecret(context);
      this.cache.set(key, result);
      logInfo('llm_secret_call_completed', {
        candidateId: context.candidate.id,
        candidateType: context.candidate.type,
        durationMs: Date.now() - startedAt,
        isSecret: result.is_secret,
        secretType: result.secret_type,
        severity: result.severity,
        confidence: result.confidence,
        reasonLength: result.reason.length,
      });
      return result;
    } catch (error) {
      logError('llm_secret_call_failed', {
        candidateId: context.candidate.id,
        candidateType: context.candidate.type,
        durationMs: Date.now() - startedAt,
        ...errorFields(error),
      });
      throw error;
    }
  }

  async analyzeBatch(contexts: SecretContext[]): Promise<LLMSecretBatchResult[]> {
    if (!this.provider || contexts.length === 0) {
      logInfo('llm_secret_batch_skipped', {
        providerEnabled: Boolean(this.provider),
        batchSize: contexts.length,
        reason: !this.provider ? 'provider is not configured' : 'empty batch',
      });
      return [];
    }

    if (this.provider.analyzeSecretsBatch) {
      logInfo('llm_secret_batch_call_start', {
        batchSize: contexts.length,
        mode: 'provider-batch',
        candidates: contexts.map((context) => ({
          candidateId: context.candidate.id,
          candidateType: context.candidate.type,
          valueLength: context.candidate.value.length,
          contextLength: context.context.length,
        })),
      });
      const startedAt = Date.now();
      try {
        const results = await this.provider.analyzeSecretsBatch(contexts);
        logInfo('llm_secret_batch_call_completed', {
          batchSize: contexts.length,
          resultCount: results.length,
          durationMs: Date.now() - startedAt,
          confirmedCount: results.filter((result) => result.is_secret).length,
          rejectedCount: results.filter((result) => !result.is_secret).length,
          resultIds: results.map((result) => result.id),
        });
        return results;
      } catch (error) {
        logError('llm_secret_batch_call_failed', {
          batchSize: contexts.length,
          durationMs: Date.now() - startedAt,
          ...errorFields(error),
        });
        throw error;
      }
    }

    logInfo('llm_secret_batch_call_start', {
      batchSize: contexts.length,
      mode: 'single-candidate-fallback',
    });
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

  runtimeStatus(): { enabled: boolean; supportsBatch: boolean } {
    return {
      enabled: Boolean(this.provider),
      supportsBatch: Boolean(this.provider?.analyzeSecretsBatch),
    };
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
