import type { FindingReviewContext, LLMFindingReviewResult, LLMProvider } from '../../types/llm.js';
import type { AnalyzeMode, FindingResult } from '../../types/results.js';
import { sha256 } from '../../utils/hash.js';
import { errorFields, logError, logInfo } from '../../utils/logger.js';

export interface FindingReviewOutput {
  findings: FindingResult[];
  stats: {
    candidateCount: number;
    reviewedCount: number;
    confirmedCount: number;
    rejectedCount: number;
    droppedCount: number;
    batchCount: number;
  };
}

const LLM_FINDING_BATCH_SIZE = 10;

export class LLMFindingAnalyzer {
  constructor(private readonly provider?: LLMProvider) {}

  isEnabled(): boolean {
    return Boolean(this.provider?.analyzeFindingsBatch);
  }

  async reviewFindings(findings: FindingResult[], mode: AnalyzeMode): Promise<FindingReviewOutput> {
    const enabled = this.isEnabled();
    const stats = {
      candidateCount: findings.length,
      reviewedCount: 0,
      confirmedCount: 0,
      rejectedCount: 0,
      droppedCount: 0,
      batchCount: 0,
    };

    logInfo('llm_finding_review_decision', {
      mode,
      llmEnabled: Boolean(this.provider),
      findingReviewEnabled: enabled,
      candidateCount: findings.length,
      reason: mode !== 'full'
        ? 'mode is not full'
        : !this.provider
          ? 'llm provider is not configured'
          : !this.provider.analyzeFindingsBatch
            ? 'llm provider does not support finding review'
            : findings.length === 0
              ? 'no findings'
              : 'llm finding review will run',
    });

    const analyzeBatch = this.provider?.analyzeFindingsBatch?.bind(this.provider);

    if (mode !== 'full' || !enabled || !this.provider || !analyzeBatch || findings.length === 0) {
      logInfo('llm_finding_review_not_requested', {
        mode,
        llmEnabled: Boolean(this.provider),
        findingReviewEnabled: enabled,
        candidateCount: findings.length,
        reason: mode !== 'full'
          ? 'mode is not full'
          : !this.provider
            ? 'llm provider is not configured'
            : !enabled
              ? 'llm provider does not support finding review'
              : 'no findings',
      });
      return { findings, stats };
    }

    const reviewed: FindingResult[] = [];
    const contexts = findings.map((finding) => ({ id: findingId(finding), finding }));

    for (const batch of chunks(contexts, LLM_FINDING_BATCH_SIZE)) {
      stats.batchCount += 1;
      logInfo('llm_finding_batch_start', {
        batchIndex: stats.batchCount,
        batchSize: batch.length,
        findingCount: contexts.length,
        findings: batch.map((context) => findingLogFields(context)),
      });
      const startedAt = Date.now();
      try {
        const results = await analyzeBatch(batch);
        const byId = new Map(results.map((result) => [result.id, result]));

        for (const context of batch) {
          const result = byId.get(context.id);
          stats.reviewedCount += 1;
          if (result?.is_risk) {
            reviewed.push(applyFindingReview(context.finding, result));
            stats.confirmedCount += 1;
          } else {
            stats.rejectedCount += 1;
          }
          logInfo('llm_finding_reviewed', {
            batchIndex: stats.batchCount,
            ...findingLogFields(context),
            reviewed: Boolean(result),
            isRisk: Boolean(result?.is_risk),
            category: result?.category,
            type: result?.type,
            severity: result?.severity,
            confidence: result?.confidence,
            reasonLength: result?.reason.length ?? 0,
          });
        }

        logInfo('llm_finding_batch_completed', {
          batchIndex: stats.batchCount,
          batchSize: batch.length,
          resultCount: results.length,
          durationMs: Date.now() - startedAt,
          reviewedCount: stats.reviewedCount,
          confirmedCount: stats.confirmedCount,
          rejectedCount: stats.rejectedCount,
        });
      } catch (error) {
        stats.droppedCount += batch.length;
        reviewed.push(...batch.map((context) => ({
          ...context.finding,
          llmReview: {
            confirmed: false,
            category: context.finding.category,
            type: context.finding.type,
            severity: context.finding.severity,
            confidence: context.finding.confidence,
            reason: 'LLM finding review failed; original rule finding was preserved.',
          },
        })));
        logError('llm_finding_batch_failed', {
          batchIndex: stats.batchCount,
          batchSize: batch.length,
          durationMs: Date.now() - startedAt,
          preservedCount: batch.length,
          ...errorFields(error),
        });
      }
    }

    return { findings: reviewed, stats };
  }
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

function findingId(finding: FindingResult): string {
  return sha256(`${finding.category}:${finding.type}:${finding.source}:${finding.value ?? ''}:${finding.evidence ?? ''}`);
}

function findingLogFields(context: FindingReviewContext): Record<string, unknown> {
  return {
    findingId: context.id,
    category: context.finding.category,
    type: context.finding.type,
    source: context.finding.source,
    severity: context.finding.severity,
    confidence: context.finding.confidence,
    valueLength: context.finding.value?.length ?? 0,
    evidenceLength: context.finding.evidence?.length ?? 0,
  };
}

function chunks<T>(values: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) {
    result.push(values.slice(index, index + size));
  }
  return result;
}
