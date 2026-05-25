import type { LLMSecretAnalyzer } from '../../llm/analyzers/llmSecretAnalyzer.js';
import type { SecretContext } from '../../types/llm.js';
import type { AnalyzeMode, ApiResult, SecretResult } from '../../types/results.js';
import { uniqueBy } from '../../utils/dedupe.js';
import { errorFields, logError, logInfo } from '../../utils/logger.js';
import { extractSecretContext } from './contextExtractor.js';
import { findSecretCandidates, findSecretCandidatesInText } from './secretCandidateFinder.js';
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

export interface SecretRuleExtractionOutput {
  secrets: SecretResult[];
  contexts: SecretContext[];
  astCandidateCount: number;
  textCandidateCount: number;
}

const LLM_BATCH_SIZE = 10;

export function extractSecretRules(
  ast: t.File,
  content: string,
  apis: ApiResult[],
  options?: { astFallbackUsed?: boolean },
): SecretRuleExtractionOutput {
  const astCandidates = findSecretCandidates(ast, content);
  const textCandidates = options?.astFallbackUsed ? findSecretCandidatesInText(content) : [];
  const candidates = uniqueBy([...astCandidates, ...textCandidates], (candidate) => candidate.value);
  const contexts = candidates.map((candidate) => extractSecretContext(content, candidate, apis));

  return {
    secrets: uniqueBy(contexts.map((context) => fallbackSecret(context)), (secret) => `${secret.type}:${secret.value ?? ''}:${secret.evidence ?? ''}`),
    contexts,
    astCandidateCount: astCandidates.length,
    textCandidateCount: textCandidates.length,
  };
}

export async function analyzeSecrets(
  ast: t.File,
  content: string,
  apis: ApiResult[],
  mode: AnalyzeMode,
  llmAnalyzer?: LLMSecretAnalyzer,
  options?: { astFallbackUsed?: boolean },
): Promise<SecretAnalysisOutput> {
  const ruleExtraction = extractSecretRules(ast, content, apis, options);
  const contexts = ruleExtraction.contexts;
  const secrets: SecretResult[] = [];
  let queuedCount = 0;
  let droppedCount = 0;
  let reviewedCount = 0;
  let confirmedCount = 0;
  let rejectedCount = 0;
  let batchCount = 0;
  const llmEnabled = Boolean(llmAnalyzer?.isEnabled());

  const fallbackById = new Map<string, SecretResult>();
  for (const context of contexts) {
    fallbackById.set(context.candidate.id, fallbackSecret(context));
  }

  logInfo('llm_secret_analysis_decision', {
    mode,
    llmEnabled,
    llmSupportsBatch: llmAnalyzer?.runtimeStatus().supportsBatch ?? false,
    candidateCount: contexts.length,
    astCandidateCount: ruleExtraction.astCandidateCount,
    textCandidateCount: ruleExtraction.textCandidateCount,
    contextCount: contexts.length,
    astFallbackUsed: options?.astFallbackUsed === true,
    reason: mode !== 'full'
      ? 'mode is not full'
      : !llmEnabled
        ? 'llm analyzer is not enabled'
        : contexts.length === 0
          ? 'no secret candidates'
          : 'llm batch review will run',
  });

  if (mode !== 'full' || !llmEnabled || contexts.length === 0) {
    logInfo('llm_secret_review_not_requested', {
      mode,
      llmEnabled,
      candidateCount: contexts.length,
      astCandidateCount: ruleExtraction.astCandidateCount,
      textCandidateCount: ruleExtraction.textCandidateCount,
      astFallbackUsed: options?.astFallbackUsed === true,
      reason: mode !== 'full'
        ? 'mode is not full'
        : !llmEnabled
          ? 'llm analyzer is not enabled'
          : 'no secret candidates',
    });
  }

  if (mode === 'full' && llmEnabled && llmAnalyzer) {
    for (const batch of chunks(contexts, LLM_BATCH_SIZE)) {
      batchCount += 1;
      queuedCount += batch.length;
      logInfo('llm_secret_batch_start', {
        batchIndex: batchCount,
        batchSize: batch.length,
        candidateCount: contexts.length,
        candidates: batch.map((context) => candidateLogFields(context)),
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
          logInfo('llm_secret_candidate_reviewed', {
            batchIndex: batchCount,
            ...candidateLogFields(context),
            reviewed: Boolean(llm),
            isSecret: Boolean(llm?.is_secret),
            secretType: llm?.secret_type,
            severity: llm?.severity,
            confidence: llm?.confidence,
            reasonLength: llm?.reason.length ?? 0,
          });
        }
        logInfo('llm_secret_batch_completed', {
          batchIndex: batchCount,
          batchSize: batch.length,
          resultCount: results.length,
          reviewedCount,
          confirmedCount,
          rejectedCount,
        });
      } catch (error) {
        logError('llm_secret_batch_failed', {
          batchIndex: batchCount,
          batchSize: batch.length,
          ...errorFields(error),
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
    logInfo('llm_secret_fallback_used', {
      mode,
      llmEnabled,
      fallbackCount: secrets.length,
      candidateCount: contexts.length,
    });
  }

  return {
    secrets: uniqueBy(secrets, (secret) => `${secret.type}:${secret.value ?? ''}:${secret.evidence ?? ''}`),
    contexts,
    llm: {
      enabled: llmEnabled,
      candidateCount: contexts.length,
      queuedCount,
      droppedCount,
      reviewedCount,
      confirmedCount,
      rejectedCount,
      batchCount,
    },
  };
}

function fallbackSecret(context: SecretContext): SecretResult {
  return {
    type: context.candidate.type,
    value: context.candidate.value,
    severity: context.candidate.severity,
    confidence: context.candidate.type === 'html-password-input' ? 0.35 : 0.75,
    source: 'regex',
    evidence: context.candidate.context ?? context.candidate.evidence,
  };
}

function candidateLogFields(context: SecretContext): Record<string, unknown> {
  return {
    candidateId: context.candidate.id,
    candidateType: context.candidate.type,
    candidateSeverity: context.candidate.severity,
    valueLength: context.candidate.value.length,
    valueHash: context.candidate.id,
    contextLength: context.context.length,
    nearbyApiCount: context.nearbyApis.length,
  };
}

function chunks<T>(values: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) {
    result.push(values.slice(index, index + size));
  }
  return result;
}
