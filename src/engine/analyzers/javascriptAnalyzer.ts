import { parseJavaScript } from '../parser/jsParser.js';
import { collectStringConstants } from '../propagation/stringResolver.js';
import { buildWrapperRegistry } from '../wrapper/wrapperRegistry.js';
import { extractApis } from '../../extractors/api/apiExtractor.js';
import { analyzeRisks } from '../../extractors/risk/riskAnalyzer.js';
import { analyzeSecrets } from '../../extractors/secret/secretAnalyzer.js';
import { extractAssets } from '../../extractors/assets/assetExtractor.js';
import { enrichApisWithBaseUrl, extractBaseUrlCandidates } from '../../extractors/api/baseUrlExtractor.js';
import { LLMSecretAnalyzer } from '../../llm/analyzers/llmSecretAnalyzer.js';
import { createLLMProvider } from '../../llm/providers/providerFactory.js';
import type { AnalysisResponse, AnalyzeMode } from '../../types/results.js';
import { errorFields, logError, logInfo } from '../../utils/logger.js';

const sharedLLMAnalyzer = new LLMSecretAnalyzer(createLLMProvider());

export async function analyzeJavaScript(input: { url?: string; content: string; mode?: AnalyzeMode }): Promise<AnalysisResponse> {
  const startedAt = Date.now();
  try {
    logInfo('analyze_js_start', {
      url: input.url,
      mode: input.mode ?? 'fast',
      contentLength: input.content.length,
    });
    const ast = parseJavaScript(input.content);
    const constants = collectStringConstants(ast);
    const wrappers = buildWrapperRegistry(ast);
    const apiExtraction = extractApis(ast, constants, wrappers);
    apiExtraction.apis = enrichApisWithBaseUrl(apiExtraction.apis, extractBaseUrlCandidates(ast, input.url));
    const assets = extractAssets(ast);
    const secretExtraction = await analyzeSecrets(ast, input.content, apiExtraction.apis, input.mode ?? 'fast', sharedLLMAnalyzer);
    const risk = analyzeRisks(ast, apiExtraction.apis);

    const response: AnalysisResponse = {
      success: true,
      url: input.url,
      apis: apiExtraction.apis,
      assets,
      params: apiExtraction.params,
      auth: apiExtraction.auth,
      secrets: secretExtraction.secrets,
      risk,
    };
    logInfo('analyze_js_success', {
      url: input.url,
      durationMs: Date.now() - startedAt,
      apiCount: response.apis.length,
      assetCount: response.assets.length,
      paramCount: response.params.length,
      secretCount: response.secrets.length,
      riskCount: response.risk.length,
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
