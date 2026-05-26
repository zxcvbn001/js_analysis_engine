import { createHash } from 'node:crypto';
import type { AnalysisApiResponse, AnalysisResult, AnalyzeMode, FindingResult } from '../types/results.js';

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

export interface RequestLogSummary {
  hasUrl: boolean;
  urlHost?: string;
  urlPath?: string;
  hasContent: boolean;
  inputContentLength: number;
  inputContentLineCount: number;
  inputContentSha256?: string;
  async: boolean;
  responseMode: 'full' | 'compact';
  fastMode?: boolean;
  requestedMode?: AnalyzeMode;
  mode: AnalyzeMode;
  llmExpected: boolean;
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

export function summarizeAnalyzeRequest(input: {
  url?: string;
  content?: string;
  async?: boolean;
  responseMode: 'full' | 'compact';
  fastMode?: boolean;
  requestedMode?: AnalyzeMode;
  mode: AnalyzeMode;
}): RequestLogSummary {
  const trimmedContent = input.content?.trim() ?? '';
  const url = parseUrl(input.url);
  return {
    hasUrl: Boolean(input.url?.trim()),
    urlHost: url?.host,
    urlPath: url?.pathname,
    hasContent: Boolean(trimmedContent),
    inputContentLength: input.content?.length ?? 0,
    inputContentLineCount: trimmedContent ? input.content?.split(/\r?\n/).length ?? 0 : 0,
    inputContentSha256: trimmedContent ? createHash('sha256').update(input.content ?? '').digest('hex') : undefined,
    async: input.async === true,
    responseMode: input.responseMode,
    fastMode: input.fastMode,
    requestedMode: input.requestedMode,
    mode: input.mode,
    llmExpected: input.mode === 'full',
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

export function summarizeApiResponse(response: AnalysisApiResponse): Record<string, unknown> {
  if (!response.success) {
    return {
      success: false,
      errorMessage: response.error.message,
    };
  }

  return {
    success: true,
    endpointCount: response.summary.endpointCount,
    leakCount: response.summary.leakCount,
    jsFileCount: response.summary.jsFileCount,
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

function parseUrl(value?: string): URL | undefined {
  if (!value) {
    return undefined;
  }

  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}
