import { parseJavaScript } from '../parser/jsParser.js';
import { collectStringConstants } from '../propagation/stringResolver.js';
import { buildWrapperRegistry } from '../wrapper/wrapperRegistry.js';
import { extractApis } from '../../extractors/api/apiExtractor.js';
import { analyzeRisks } from '../../extractors/risk/riskAnalyzer.js';
import { analyzeSecrets } from '../../extractors/secret/secretAnalyzer.js';
import { extractAssets } from '../../extractors/assets/assetExtractor.js';
import { enrichApisWithBaseUrl, extractBaseUrlCandidates } from '../../extractors/api/baseUrlExtractor.js';
import { analyzeFindings } from '../../extractors/findings/findingAnalyzer.js';
import { filterUnconfirmedSensitiveFindings, groupFindings } from '../../extractors/findings/findingGrouper.js';
import { LLMSecretAnalyzer } from '../../llm/analyzers/llmSecretAnalyzer.js';
import { createLLMProvider } from '../../llm/providers/providerFactory.js';
import type { AnalysisResponse, AnalyzeMode } from '../../types/results.js';
import { summarizeAnalysis } from '../../utils/analysisSummary.js';
import { errorFields, logError, logInfo } from '../../utils/logger.js';

const sharedLLMAnalyzer = new LLMSecretAnalyzer(createLLMProvider());

export async function analyzeJavaScript(input: { url?: string; content: string; mode?: AnalyzeMode; llmAnalyzer?: LLMSecretAnalyzer }): Promise<AnalysisResponse> {
  const startedAt = Date.now();
  try {
    logInfo('analyze_js_start', {
      url: input.url,
      mode: input.mode ?? 'full',
      contentLength: input.content.length,
    });
    const ast = parseJavaScript(input.content);
    const constants = collectStringConstants(ast);
    const wrappers = buildWrapperRegistry(ast);
    const apiExtraction = extractApis(ast, constants, wrappers);
    apiExtraction.apis = enrichApisWithBaseUrl(apiExtraction.apis, extractBaseUrlCandidates(ast, input.url));
    const assets = extractAssets(ast);
    const activeLLMAnalyzer = input.llmAnalyzer ?? sharedLLMAnalyzer;
    const secretExtraction = await analyzeSecrets(ast, input.content, apiExtraction.apis, input.mode ?? 'full', activeLLMAnalyzer);
    const risk = analyzeRisks(ast, apiExtraction.apis);
    const rawFindings = analyzeFindings({
      ast,
      content: input.content,
      apis: apiExtraction.apis,
      assets,
      secrets: secretExtraction.secrets,
      risk,
    });
    const findings = filterUnconfirmedSensitiveFindings({
      findings: rawFindings,
      secrets: secretExtraction.secrets,
      requireConfirmedSecrets: (input.mode ?? 'full') === 'full' && secretExtraction.llm.enabled,
    });
    const groups = groupFindings({
      apis: apiExtraction.apis,
      assets,
      secrets: secretExtraction.secrets,
      findings,
    });

    const response: AnalysisResponse = {
      success: true,
      url: input.url,
      apis: apiExtraction.apis,
      assets,
      params: apiExtraction.params,
      auth: apiExtraction.auth,
      secrets: secretExtraction.secrets,
      risk,
      findings,
      groups,
      meta: {
        analysis: {
          llm: {
            ...secretExtraction.llm,
            batchSize: 10,
          },
        },
      },
    };
    logInfo('analyze_js_success', {
      url: input.url,
      durationMs: Date.now() - startedAt,
      ...summarizeAnalysis(response),
    });
    return response;
  } catch (error) {
    logError('analyze_js_failed', {
      url: input.url,
      durationMs: Date.now() - startedAt,
      ...errorFields(error),
    });
    return {
      success: false,
      error: {
        message: error instanceof Error ? error.message : 'Unknown analysis error',
      },
    };
  }
}
