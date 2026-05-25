import type { AnalysisApiResponse, AnalysisResponse, CompactAnalysisResult } from '../../types/results.js';

export function formatAnalysisResponse(
  result: AnalysisResponse,
  responseMode: 'full' | 'compact',
): AnalysisApiResponse {
  if (!result.success || responseMode === 'full') {
    return result;
  }

  const compact: CompactAnalysisResult = {
    success: true,
    url: result.url,
    summary: {
      apiCount: result.apis.length,
      assetCount: result.assets.length,
      paramCount: result.params.length,
      authCount: result.auth.length,
      secretCount: result.secrets.length,
      riskCount: result.risk.length,
      findingCount: result.findings.length,
      endpointCount: result.groups.endpoints.count,
      exposureCount: result.groups.exposures.count,
      scriptCount: result.groups.scripts.count,
      llm: {
        enabled: result.meta.analysis.llm.enabled,
        reviewedCount: result.meta.analysis.llm.reviewedCount,
        confirmedCount: result.meta.analysis.llm.confirmedCount,
        rejectedCount: result.meta.analysis.llm.rejectedCount,
        findingReviewedCount: result.meta.analysis.llm.findingReviewedCount,
        findingConfirmedCount: result.meta.analysis.llm.findingConfirmedCount,
        findingRejectedCount: result.meta.analysis.llm.findingRejectedCount,
      },
    },
    apis: result.apis,
    assets: result.assets,
    params: result.params,
    auth: result.auth,
    secrets: result.secrets,
    findings: result.findings,
  };

  return compact;
}
