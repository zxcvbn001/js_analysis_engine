import { buildFunctionRegistry } from '../callgraph/functionRegistry.js';
import { parseJavaScriptWithDiagnostics } from '../parser/jsParser.js';
import { collectStringConstants } from '../propagation/stringResolver.js';
import { buildWrapperRegistry } from '../wrapper/wrapperRegistry.js';
import { extractApis } from '../../extractors/api/apiExtractor.js';
import { analyzeRisks } from '../../extractors/risk/riskAnalyzer.js';
import { extractSecretRules } from '../../extractors/secret/secretAnalyzer.js';
import { extractAssets } from '../../extractors/assets/assetExtractor.js';
import { enrichApisWithBaseUrl, extractBaseUrlCandidates } from '../../extractors/api/baseUrlExtractor.js';
import { analyzeFindings } from '../../extractors/findings/findingAnalyzer.js';
import { filterUnconfirmedSensitiveFindings, groupFindings } from '../../extractors/findings/findingGrouper.js';
import { extractTextApis, extractTextAssets, extractTextBaseUrlCandidates } from '../../extractors/text/textFallbackExtractor.js';
import { LLMSecretAnalyzer } from '../../llm/analyzers/llmSecretAnalyzer.js';
import { LLMUnifiedAnalyzer } from '../../llm/analyzers/llmUnifiedAnalyzer.js';
import { createLLMProvider } from '../../llm/providers/providerFactory.js';
import type { AnalysisResponse, AnalyzeMode, AssetResult } from '../../types/results.js';
import { summarizeAnalysis } from '../../utils/analysisSummary.js';
import { errorFields, logError, logInfo, logWarn } from '../../utils/logger.js';

const sharedLLMProvider = createLLMProvider();
const sharedLLMAnalyzer = new LLMSecretAnalyzer(sharedLLMProvider);
const sharedUnifiedLLMAnalyzer = new LLMUnifiedAnalyzer(sharedLLMProvider);

export async function analyzeJavaScript(input: {
  url?: string;
  content: string;
  mode?: AnalyzeMode;
  llmAnalyzer?: LLMSecretAnalyzer;
  unifiedLlmAnalyzer?: LLMUnifiedAnalyzer;
}): Promise<AnalysisResponse> {
  const startedAt = Date.now();
  try {
    logInfo('analyze_js_start', {
      url: input.url,
      mode: input.mode ?? 'full',
      contentLength: input.content.length,
    });
    const parsed = parseJavaScriptWithDiagnostics(input.content);
    if (!parsed.ok) {
      logWarn('analyze_js_parse_failed', {
        url: input.url,
        contentLength: input.content.length,
        ...parsed.diagnostics,
        ...errorFields(parsed.error),
      });
    } else if (parsed.errorCount > 0 || parsed.diagnostics.looksLikeHtml || parsed.diagnostics.nulByteCount > 0 || parsed.diagnostics.replacementCharCount > 0) {
      logWarn('analyze_js_parse_suspicious', {
        url: input.url,
        parserErrorCount: parsed.errorCount,
        ...parsed.diagnostics,
      });
    }

    const ast = parsed.ast;
    const functionRegistry = buildFunctionRegistry(ast);
    const constants = collectStringConstants(ast, functionRegistry);
    const wrappers = buildWrapperRegistry(ast);
    const astApiExtraction = extractApis(ast, constants, wrappers, functionRegistry);
    const textApiExtraction = parsed.fallbackUsed ? extractTextApis(input.content) : { apis: [], params: [], auth: [] };
    const baseUrlCandidates = [
      ...extractBaseUrlCandidates(ast, input.url),
      ...(parsed.fallbackUsed ? extractTextBaseUrlCandidates(input.content) : []),
    ];
    const apiExtraction = {
      apis: enrichApisWithBaseUrl([...astApiExtraction.apis, ...textApiExtraction.apis], baseUrlCandidates),
      params: [...astApiExtraction.params, ...textApiExtraction.params],
      auth: [...new Set([...astApiExtraction.auth, ...textApiExtraction.auth])],
    };
    const assets: AssetResult[] = [...extractAssets(ast), ...(parsed.fallbackUsed ? extractTextAssets(input.content) : [])];

    if (parsed.fallbackUsed) {
      logInfo('analyze_js_text_fallback_completed', {
        url: input.url,
        textApiCount: textApiExtraction.apis.length,
        textParamCount: textApiExtraction.params.length,
        textAuthCount: textApiExtraction.auth.length,
        textAssetCount: assets.length,
        baseUrlCandidateCount: baseUrlCandidates.length,
      });
    }

    const activeLLMAnalyzer = input.llmAnalyzer ?? sharedLLMAnalyzer;
    logInfo('analyze_js_llm_runtime', {
      url: input.url,
      mode: input.mode ?? 'full',
      ...activeLLMAnalyzer.runtimeStatus(),
    });
    const secretRules = extractSecretRules(ast, input.content, apiExtraction.apis, {
      astFallbackUsed: parsed.fallbackUsed,
    });
    const risk = analyzeRisks(ast, apiExtraction.apis);
    const rawFindings = analyzeFindings({
      ast,
      content: input.content,
      apis: apiExtraction.apis,
      assets,
      secrets: secretRules.secrets,
      risk,
    });
    const unifiedReview = await (input.unifiedLlmAnalyzer ?? sharedUnifiedLLMAnalyzer).review({
      mode: input.mode ?? 'full',
      secrets: secretRules.contexts,
      findings: rawFindings,
      apis: apiExtraction.apis,
    });
    const findings = filterUnconfirmedSensitiveFindings({
      findings: unifiedReview.findings,
      secrets: unifiedReview.secrets,
      requireConfirmedSecrets: (input.mode ?? 'full') === 'full' && unifiedReview.llm.enabled,
    });
    const groups = groupFindings({
      apis: apiExtraction.apis,
      assets,
      secrets: unifiedReview.secrets,
      findings,
    });

    const response: AnalysisResponse = {
      success: true,
      url: input.url,
      apis: apiExtraction.apis,
      assets,
      params: apiExtraction.params,
      auth: apiExtraction.auth,
      secrets: unifiedReview.secrets,
      risk,
      findings,
      groups,
      meta: {
        analysis: {
          llm: {
            ...unifiedReview.llm,
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
