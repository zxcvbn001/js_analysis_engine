import type {
  ApiResult,
  AssetResult,
  AnalysisApiResponse,
  AnalysisResponse,
  BurpAnalysisResult,
  EndpointResult,
  FindingResult,
  JsFileResult,
  LeakResult,
  SecretResult,
} from '../../types/results.js';
import { uniqueBy } from '../../utils/dedupe.js';

const leakFindingCategories = new Set([
  'API 信息',
  '敏感凭据',
  '权限信息',
  '云配置',
  '第三方配置',
  '调试信息',
  '内网信息',
  'JWT/OAuth',
  '路由信息',
]);

export function formatAnalysisResponse(
  result: AnalysisResponse,
  _responseMode: 'full' | 'compact',
): AnalysisApiResponse {
  if (!result.success) {
    return result;
  }

  const endpoints = toEndpoints(result.apis, result.findings);
  const jsFiles = toJsFiles(result.assets, result.findings);
  const leaks = toLeaks(result.secrets, result.findings, endpoints);

  const response: BurpAnalysisResult = {
    success: true,
    url: result.url,
    summary: {
      endpointCount: endpoints.length,
      leakCount: leaks.length,
      jsFileCount: jsFiles.length,
    },
    leaks,
    endpoints,
    jsFiles,
  };

  return response;
}

function toEndpoints(apis: ApiResult[], findings: FindingResult[]): EndpointResult[] {
  const evidenceByUrl = new Map(
    findings
      .filter((finding) => finding.source === 'api' && finding.type === 'api-endpoint' && finding.value)
      .map((finding) => [finding.value ?? '', finding.evidence]),
  );
  const endpoints = apis
    .filter((api) => (api.kind ?? 'api') === 'api')
    .map((api) => ({
      ...api,
      evidence: evidenceByUrl.get(api.resolvedUrl ?? api.url) ?? evidenceByUrl.get(api.url) ?? `${api.method ?? 'GET'} ${api.resolvedUrl ?? api.url}`,
    }));

  return uniqueBy(endpoints, (endpoint) => `${endpoint.method ?? ''}:${endpoint.url}:${endpoint.resolvedUrl ?? ''}:${endpoint.source ?? ''}`);
}

function toJsFiles(assets: AssetResult[], findings: FindingResult[]): JsFileResult[] {
  const assetFiles: JsFileResult[] = assets.map((asset) => ({
    url: asset.url,
    type: asset.type,
    chunkName: asset.chunkName,
    source: asset.source,
    confidence: 0.85,
  }));
  const findingFiles = findings
    .filter((finding) => (finding.source === 'asset' || finding.category === 'webpack模块') && finding.value)
    .map((finding) => ({
      url: finding.value ?? '',
      type: jsFileType(finding),
      chunkName: finding.type === 'hidden-asset' ? chunkNameFromUrl(finding.value ?? '') : undefined,
      source: finding.source === 'asset' ? 'webpack-runtime' : finding.source,
      confidence: finding.confidence,
      evidence: finding.evidence,
    }));

  return uniqueBy([...assetFiles, ...findingFiles], (jsFile) => `${jsFile.type}:${jsFile.url}:${jsFile.chunkName ?? ''}`);
}

function toLeaks(secrets: SecretResult[], findings: FindingResult[], endpoints: EndpointResult[]): LeakResult[] {
  const secretLeaks = secrets.map(secretToLeak);
  const secretKeys = new Set(secretLeaks.map((leak) => leakKey(leak)));
  const endpointValues = new Set(endpoints.flatMap((endpoint) => [endpoint.url, endpoint.resolvedUrl]).filter((value): value is string => Boolean(value)));
  const findingLeaks = findings
    .filter((finding) => isLeakFinding(finding, endpointValues))
    .filter((finding) => !(finding.source === 'secret' && secretKeys.has(leakKey(finding))))
    .map(findingToLeak);

  return uniqueBy([...secretLeaks, ...findingLeaks], leakKey);
}

function isLeakFinding(finding: FindingResult, endpointValues: Set<string>): boolean {
  if (!leakFindingCategories.has(finding.category)) {
    return false;
  }
  if (finding.category !== 'API 信息') {
    return true;
  }

  const value = finding.value ?? '';
  if (finding.type === 'api-endpoint' || finding.source === 'api' || endpointValues.has(value)) {
    return false;
  }
  return /^https?:\/\//i.test(value) || /(?:gateway|baseUrl|baseURL|apiHost|apiBase|dev|test|uat|stage|staging|pre|prod)/i.test(value);
}

function secretToLeak(secret: SecretResult): LeakResult {
  return {
    category: '敏感凭据',
    type: secret.type,
    value: secret.value,
    severity: secret.severity,
    confidence: secret.confidence,
    source: secret.source,
    evidence: secret.evidence,
  };
}

function findingToLeak(finding: FindingResult): LeakResult {
  return {
    category: finding.category,
    type: finding.type,
    value: finding.value,
    severity: finding.severity,
    confidence: finding.confidence,
    source: finding.source,
    evidence: finding.evidence,
  };
}

function leakKey(leak: Pick<LeakResult, 'category' | 'type' | 'value' | 'evidence'>): string {
  return `${leak.category}:${leak.type}:${leak.value ?? ''}:${leak.evidence ?? ''}`;
}

function jsFileType(finding: FindingResult): JsFileResult['type'] {
  const value = finding.value ?? '';
  if (finding.type === 'hidden-asset' && /\.(?:m?js)(?:$|\?)/i.test(value)) {
    return 'script';
  }
  if (finding.type === 'hidden-asset' && /\.css(?:$|\?)/i.test(value)) {
    return 'style';
  }
  return finding.category === 'webpack模块' ? 'webpack-module' : 'asset';
}

function chunkNameFromUrl(url: string): string | undefined {
  const fileName = url.split(/[/?#]/).filter(Boolean).at(-1);
  if (!fileName) {
    return undefined;
  }
  return fileName.replace(/\.[a-f0-9]{6,}(?=\.(?:m?js|css|map)$)/i, '').replace(/\.(?:m?js|css|map)$/i, '');
}
