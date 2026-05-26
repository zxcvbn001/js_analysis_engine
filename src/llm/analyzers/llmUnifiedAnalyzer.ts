import type { FindingReviewContext, LLMFindingReviewResult, LLMProvider, LLMSecretBatchResult, SecretContext } from '../../types/llm.js';
import type { ApiResult, AnalyzeMode, FindingResult, SecretResult } from '../../types/results.js';
import { getConfig } from '../../config/appConfig.js';
import { sha256 } from '../../utils/hash.js';
import { errorFields, logError, logInfo } from '../../utils/logger.js';

export interface UnifiedReviewOutput {
  secrets: SecretResult[];
  findings: FindingResult[];
  llm: {
    enabled: boolean;
    candidateCount: number;
    queuedCount: number;
    droppedCount: number;
    reviewedCount: number;
    confirmedCount: number;
    rejectedCount: number;
    batchCount: number;
    findingCandidateCount: number;
    findingReviewedCount: number;
    findingConfirmedCount: number;
    findingRejectedCount: number;
    findingDroppedCount: number;
    findingBatchCount: number;
  };
}

const UNIFIED_SECRET_BATCH_SIZE = 5;
const UNIFIED_FINDING_BATCH_SIZE = 10;

export class LLMUnifiedAnalyzer {
  constructor(private readonly provider?: LLMProvider) {}

  runtimeStatus(): { enabled: boolean; supportsUnified: boolean } {
    return {
      enabled: Boolean(this.provider),
      supportsUnified: Boolean(this.provider?.analyzeUnifiedBatch),
    };
  }

  async review(input: {
    mode: AnalyzeMode;
    secrets: SecretContext[];
    findings: FindingResult[];
    apis: ApiResult[];
  }): Promise<UnifiedReviewOutput> {
    const llmConfig = getConfig().llm;
    const enabled = Boolean(this.provider?.analyzeUnifiedBatch);
    const secretTypeAllowList = new Set(llmConfig.allowedSecretTypes);
    const findingCategoryAllowList = new Set(llmConfig.allowedFindingCategories);
    const reviewSecretsEnabled = llmConfig.reviewSecrets;
    const reviewFindingsEnabled = llmConfig.reviewFindings;
    const reviewableSecrets = input.secrets.filter((context) => reviewSecretsEnabled && matchesAllowList(secretTypeAllowList, context.candidate.type));
    const passthroughSecrets = input.secrets.filter((context) => !reviewableSecrets.includes(context));
    const reviewableFindings = input.findings.filter((finding) => reviewFindingsEnabled && matchesAllowList(findingCategoryAllowList, finding.category));
    const passthroughFindings = input.findings.filter((finding) => !reviewableFindings.includes(finding));
    const llm = {
      enabled,
      candidateCount: reviewableSecrets.length,
      queuedCount: 0,
      droppedCount: 0,
      reviewedCount: 0,
      confirmedCount: 0,
      rejectedCount: 0,
      batchCount: 0,
      findingCandidateCount: reviewableFindings.length,
      findingReviewedCount: 0,
      findingConfirmedCount: 0,
      findingRejectedCount: 0,
      findingDroppedCount: 0,
      findingBatchCount: 0,
    };

    logInfo('llm_unified_review_decision', {
      mode: input.mode,
      llmEnabled: Boolean(this.provider),
      unifiedReviewEnabled: enabled,
      secretCandidateCount: reviewableSecrets.length,
      findingCandidateCount: reviewableFindings.length,
      secretReviewEnabled: reviewSecretsEnabled,
      findingReviewEnabled: reviewFindingsEnabled,
      allowedSecretTypes: llmConfig.allowedSecretTypes,
      allowedFindingCategories: llmConfig.allowedFindingCategories,
      skippedSecretCount: passthroughSecrets.length,
      skippedFindingCount: passthroughFindings.length,
      reason: input.mode !== 'full'
        ? 'mode is not full'
        : !this.provider
          ? 'llm provider is not configured'
          : !this.provider.analyzeUnifiedBatch
            ? 'llm provider does not support unified review'
            : reviewableSecrets.length + reviewableFindings.length === 0
              ? 'no review candidates'
              : 'llm unified review will run',
    });

    const analyzeUnifiedBatch = this.provider?.analyzeUnifiedBatch?.bind(this.provider);
    if (input.mode !== 'full' || !enabled || !analyzeUnifiedBatch || reviewableSecrets.length + reviewableFindings.length === 0) {
      logInfo('llm_unified_review_not_requested', {
        mode: input.mode,
        llmEnabled: Boolean(this.provider),
        unifiedReviewEnabled: enabled,
        secretCandidateCount: reviewableSecrets.length,
        findingCandidateCount: reviewableFindings.length,
        secretReviewEnabled: reviewSecretsEnabled,
        findingReviewEnabled: reviewFindingsEnabled,
        allowedSecretTypes: llmConfig.allowedSecretTypes,
        allowedFindingCategories: llmConfig.allowedFindingCategories,
        skippedSecretCount: passthroughSecrets.length,
        skippedFindingCount: passthroughFindings.length,
      });
      return {
        secrets: input.secrets.map(fallbackSecret),
        findings: input.findings,
        llm,
      };
    }

    const secretBatches = chunks(reviewableSecrets, UNIFIED_SECRET_BATCH_SIZE);
    const findingBatches = chunks(reviewableFindings.map((finding) => ({ id: findingId(finding), finding })), UNIFIED_FINDING_BATCH_SIZE);
    const batchCount = Math.max(secretBatches.length, findingBatches.length);
    const reviewedSecrets: SecretResult[] = passthroughSecrets.map(fallbackSecret);
    const reviewedFindings: FindingResult[] = [...passthroughFindings];

    for (let index = 0; index < batchCount; index += 1) {
      const secretBatch = secretBatches[index] ?? [];
      const findingBatch = findingBatches[index] ?? [];
      llm.batchCount += secretBatch.length > 0 ? 1 : 0;
      llm.findingBatchCount += findingBatch.length > 0 ? 1 : 0;
      llm.queuedCount += secretBatch.length;
      const startedAt = Date.now();

      logInfo('llm_unified_batch_start', {
        batchIndex: index + 1,
        secretBatchSize: secretBatch.length,
        findingBatchSize: findingBatch.length,
        secretCandidateCount: reviewableSecrets.length,
        findingCandidateCount: reviewableFindings.length,
        secretIds: secretBatch.map((context) => context.candidate.id),
        findingIds: findingBatch.map((context) => context.id),
      });

      try {
        const result = await analyzeUnifiedBatch({
          secrets: secretBatch,
          findings: findingBatch,
          apis: input.apis.map((api) => ({
            url: api.resolvedUrl ?? api.url,
            method: api.method,
            params: api.params,
            headers: api.headers,
          })),
        });
        const secretResults = new Map(result.secrets.map((secret) => [secret.id, secret]));
        const findingResults = new Map(result.findings.map((finding) => [finding.id, finding]));

        for (const context of secretBatch) {
          const review = secretResults.get(context.candidate.id);
          llm.reviewedCount += 1;
          if (review?.is_secret) {
            reviewedSecrets.push(applySecretReview(context, review));
            llm.confirmedCount += 1;
          } else {
            llm.rejectedCount += 1;
          }
        }

        for (const context of findingBatch) {
          const review = findingResults.get(context.id);
          llm.findingReviewedCount += 1;
          if (review?.is_risk) {
            reviewedFindings.push(applyFindingReview(context.finding, review));
            llm.findingConfirmedCount += 1;
          } else {
            llm.findingRejectedCount += 1;
          }
        }

        logInfo('llm_unified_batch_completed', {
          batchIndex: index + 1,
          durationMs: Date.now() - startedAt,
          secretResultCount: result.secrets.length,
          findingResultCount: result.findings.length,
          confirmedSecretCount: result.secrets.filter((secret) => secret.is_secret).length,
          confirmedFindingCount: result.findings.filter((finding) => finding.is_risk).length,
        });
      } catch (error) {
        llm.droppedCount += secretBatch.length;
        llm.findingDroppedCount += findingBatch.length;
        reviewedSecrets.push(...secretBatch.map(fallbackSecret));
        reviewedFindings.push(...findingBatch.map((context) => preservedFinding(context.finding)));
        logError('llm_unified_batch_failed', {
          batchIndex: index + 1,
          durationMs: Date.now() - startedAt,
          preservedSecretCount: secretBatch.length,
          preservedFindingCount: findingBatch.length,
          ...errorFields(error),
        });
      }
    }

    return {
      secrets: dedupeSecrets(reviewedSecrets),
      findings: dedupeFindings(reviewedFindings),
      llm,
    };
  }
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

function applySecretReview(context: SecretContext, review: LLMSecretBatchResult): SecretResult {
  return {
    type: review.secret_type || context.candidate.type,
    value: context.candidate.value,
    severity: review.severity,
    confidence: review.confidence,
    source: 'llm+regex',
    evidence: review.reason || context.candidate.context || context.candidate.evidence,
  };
}

function applyFindingReview(finding: FindingResult, review: LLMFindingReviewResult): FindingResult {
  return {
    ...finding,
    category: review.category || finding.category,
    type: review.type || finding.type,
    severity: review.severity,
    confidence: review.confidence,
    source: 'llm',
    llmReview: {
      confirmed: true,
      category: review.category || finding.category,
      type: review.type || finding.type,
      severity: review.severity,
      confidence: review.confidence,
      reason: review.reason,
    },
  };
}

function preservedFinding(finding: FindingResult): FindingResult {
  return {
    ...finding,
    llmReview: {
      confirmed: false,
      category: finding.category,
      type: finding.type,
      severity: finding.severity,
      confidence: finding.confidence,
      reason: 'LLM unified review failed; original rule finding was preserved.',
    },
  };
}

function findingId(finding: FindingResult): string {
  return sha256(`${finding.category}:${finding.type}:${finding.source}:${finding.value ?? ''}:${finding.evidence ?? ''}`);
}

function chunks<T>(values: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) {
    result.push(values.slice(index, index + size));
  }
  return result;
}

function matchesAllowList(allowList: Set<string>, value: string): boolean {
  return allowList.size === 0 || allowList.has(value);
}

function dedupeSecrets(secrets: SecretResult[]): SecretResult[] {
  const seen = new Set<string>();
  return secrets.filter((secret) => {
    const key = `${secret.type}:${secret.value ?? ''}:${secret.evidence ?? ''}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function dedupeFindings(findings: FindingResult[]): FindingResult[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.category}:${finding.type}:${finding.source}:${finding.value ?? ''}:${finding.evidence ?? ''}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
