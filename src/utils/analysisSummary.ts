import { createHash } from 'node:crypto';
import type { AnalysisResult, AnalyzeMode, FindingResult } from '../types/results.js';

export interface ContentSummary {
  source: 'content' | 'download';
  hasUrl: boolean;
  contentLength: number;
  lineCount: number;
  sha256: string;
}

export interface AnalysisLogSummary {
  apiCount: number;
  apiMethodCounts: Record<string, number>;
  resolvedApiCount: number;
  assetCount: number;
  paramCount: number;
  authCount: number;
  secretCount: number;
  secretTypeCounts: Record<string, number>;
  riskCount: number;
  findingCount: number;
  findingCategoryCounts: Record<string, number>;
  highSeverityFindingCount: number;
  endpointGroupCount: number;
  exposureGroupCount: number;
  scriptGroupCount: number;
  llmEnabled: boolean;
  llmCandidateCount: number;
  llmQueuedCount: number;
  llmDroppedCount: number;
  llmReviewedCount: number;
  llmConfirmedCount: number;
  llmRejectedCount: number;
  llmBatchCount: number;
  llmBatchSize: number;
  llmFindingCandidateCount: number;
  llmFindingReviewedCount: number;
  llmFindingConfirmedCount: number;
  llmFindingRejectedCount: number;
  llmFindingDroppedCount: number;
  llmFindingBatchCount: number;
}

export function summarizeContent(input: { content: string; source: 'content' | 'download'; url?: string }): ContentSummary {
  return {
    source: input.source,
    hasUrl: Boolean(input.url),
    contentLength: input.content.length,
    lineCount: input.content.length === 0 ? 0 : input.content.split(/\r?\n/).length,
    sha256: createHash('sha256').update(input.content).digest('hex'),
  };
}

export function summarizeAnalysis(result: AnalysisResult): AnalysisLogSummary {
  return {
    apiCount: result.apis.length,
    apiMethodCounts: countBy(result.apis.map((api) => api.method ?? 'UNKNOWN')),
    resolvedApiCount: result.apis.filter((api) => Boolean(api.resolvedUrl)).length,
    assetCount: result.assets.length,
    paramCount: result.params.length,
    authCount: result.auth.length,
    secretCount: result.secrets.length,
    secretTypeCounts: countBy(result.secrets.map((secret) => secret.type)),
    riskCount: result.risk.length,
    findingCount: result.findings.length,
    findingCategoryCounts: countBy(result.findings.map((finding) => finding.category)),
    highSeverityFindingCount: result.findings.filter(isHighSeverity).length,
    endpointGroupCount: result.groups.endpoints.count,
    exposureGroupCount: result.groups.exposures.count,
    scriptGroupCount: result.groups.scripts.count,
    llmEnabled: result.meta.analysis.llm.enabled,
    llmCandidateCount: result.meta.analysis.llm.candidateCount,
    llmQueuedCount: result.meta.analysis.llm.queuedCount,
    llmDroppedCount: result.meta.analysis.llm.droppedCount,
    llmReviewedCount: result.meta.analysis.llm.reviewedCount,
    llmConfirmedCount: result.meta.analysis.llm.confirmedCount,
    llmRejectedCount: result.meta.analysis.llm.rejectedCount,
    llmBatchCount: result.meta.analysis.llm.batchCount,
    llmBatchSize: result.meta.analysis.llm.batchSize,
    llmFindingCandidateCount: result.meta.analysis.llm.findingCandidateCount,
    llmFindingReviewedCount: result.meta.analysis.llm.findingReviewedCount,
    llmFindingConfirmedCount: result.meta.analysis.llm.findingConfirmedCount,
    llmFindingRejectedCount: result.meta.analysis.llm.findingRejectedCount,
    llmFindingDroppedCount: result.meta.analysis.llm.findingDroppedCount,
    llmFindingBatchCount: result.meta.analysis.llm.findingBatchCount,
  };
}

export function summarizeMode(mode: AnalyzeMode): { mode: AnalyzeMode; llmExpected: boolean } {
  return {
    mode,
    llmExpected: mode === 'full',
  };
}

function countBy(values: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return counts;
}

function isHighSeverity(finding: FindingResult): boolean {
  return finding.severity === 'high';
}
