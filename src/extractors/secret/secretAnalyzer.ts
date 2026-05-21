import type { LLMSecretAnalyzer } from '../../llm/analyzers/llmSecretAnalyzer.js';
import type { SecretContext } from '../../types/llm.js';
import type { AnalyzeMode, ApiResult, SecretResult } from '../../types/results.js';
import { uniqueBy } from '../../utils/dedupe.js';
import { logError, logInfo } from '../../utils/logger.js';
import { extractSecretContext } from './contextExtractor.js';
import { findSecretCandidates } from './secretCandidateFinder.js';
import type * as t from '@babel/types';

export interface SecretAnalysisOutput {
  secrets: SecretResult[];
  contexts: SecretContext[];
  llm: {
    enabled: boolean;
    candidateCount: number;
    queuedCount: number;
    droppedCount: number;
    reviewedCount: number;
    confirmedCount: number;
    rejectedCount: number;
    batchCount: number;
  };
}

const LLM_BATCH_SIZE = 10;

export async function analyzeSecrets(
  ast: t.File,
  content: string,
  apis: ApiResult[],
  mode: AnalyzeMode,
  llmAnalyzer?: LLMSecretAnalyzer,
): Promise<SecretAnalysisOutput> {
  const candidates = uniqueBy(findSecretCandidates(ast, content), (candidate) => candidate.value);
  const contexts = candidates.map((candidate) => extractSecretContext(content, candidate, apis));
  const secrets: SecretResult[] = [];
  let queuedCount = 0;
  let droppedCount = 0;
  let reviewedCount = 0;
  let confirmedCount = 0;
  let rejectedCount = 0;
  let batchCount = 0;

  const fallbackById = new Map<string, SecretResult>();
  for (const context of contexts) {
    const fallback: SecretResult = {
      type: context.candidate.type,
      value: context.candidate.value,
      severity: context.candidate.severity,
      confidence: context.candidate.type === 'html-password-input' ? 0.35 : 0.75,
      source: 'regex',
      evidence: context.candidate.context ?? context.candidate.evidence,
    };
    fallbackById.set(context.candidate.id, fallback);
  }

  if (mode === 'full' && llmAnalyzer?.isEnabled()) {
    for (const batch of chunks(contexts, LLM_BATCH_SIZE)) {
      batchCount += 1;
      logInfo('llm_secret_batch_start', {
        batchIndex: batchCount,
        batchSize: batch.length,
        candidateCount: contexts.length,
      });
      try {
        const results = await llmAnalyzer.analyzeBatch(batch);
        const byId = new Map(results.map((result) => [result.id, result]));
        for (const context of batch) {
          const llm = byId.get(context.candidate.id);
          reviewedCount += 1;
          if (llm?.is_secret) {
            const fallback = fallbackById.get(context.candidate.id);
            if (fallback) {
              secrets.push(llmAnalyzer.toSecretResult(fallback, llm));
            }
            confirmedCount += 1;
          } else {
            rejectedCount += 1;
          }
        }
        logInfo('llm_secret_batch_completed', {
          batchIndex: batchCount,
          batchSize: batch.length,
          resultCount: results.length,
          reviewedCount,
          confirmedCount,
          rejectedCount,
        });
      } catch {
        logError('llm_secret_batch_failed', {
          batchIndex: batchCount,
          batchSize: batch.length,
        });
        reviewedCount += batch.length;
        droppedCount += batch.length;
      }
    }
  } else {
    for (const context of contexts) {
      const fallback = fallbackById.get(context.candidate.id);
      if (fallback) {
        secrets.push(fallback);
      }
    }
  }

  return {
    secrets: uniqueBy(secrets, (secret) => `${secret.type}:${secret.value ?? ''}:${secret.evidence ?? ''}`),
    contexts,
    llm: {
      enabled: Boolean(llmAnalyzer?.isEnabled()),
      candidateCount: candidates.length,
      queuedCount,
      droppedCount,
      reviewedCount,
      confirmedCount,
      rejectedCount,
      batchCount,
    },
  };
}

function chunks<T>(values: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) {
    result.push(values.slice(index, index + size));
  }
  return result;
}
