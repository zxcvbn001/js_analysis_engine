export type Severity = 'low' | 'medium' | 'high';
export type AnalyzeMode = 'fast' | 'full';
export type AnalysisResponseMode = 'full' | 'compact';

export interface ApiResult {
  url: string;
  resolvedUrl?: string;
  baseUrl?: string;
  kind?: 'api' | 'asset' | 'unknown';
  method?: string;
  params?: string[];
  headers?: string[];
  auth?: string;
  source?: string;
  confidence?: 'low' | 'medium' | 'high';
  notes?: string[];
}

export interface ParamResult {
  name: string;
  location: 'query' | 'body' | 'path' | 'header';
  api?: string;
  source?: string;
}

export interface SecretResult {
  type: string;
  value?: string;
  severity: Severity;
  confidence?: number;
  source?: 'regex' | 'llm' | 'llm+regex';
  evidence?: string;
}

export interface RiskResult {
  type: string;
  severity: Severity;
  evidence?: string;
}

export interface AssetResult {
  url: string;
  type: 'script' | 'style' | 'asset';
  chunkName?: string;
  source?: string;
}

export interface FindingResult {
  category: string;
  type: string;
  value?: string;
  severity: Severity;
  confidence: number;
  source: 'api' | 'asset' | 'string' | 'identifier' | 'call' | 'secret' | 'risk' | 'llm';
  evidence?: string;
  llmReview?: {
    confirmed: boolean;
    category: string;
    type: string;
    severity: Severity;
    confidence: number;
    reason: string;
  };
}

export interface FindingGroups {
  endpoints: {
    apis: ApiResult[];
    findings: FindingResult[];
    count: number;
  };
  exposures: {
    secrets: SecretResult[];
    findings: FindingResult[];
    count: number;
  };
  scripts: {
    assets: AssetResult[];
    findings: FindingResult[];
    count: number;
  };
}

export interface AnalysisMeta {
  analysis: {
    llm: {
      enabled: boolean;
      candidateCount: number;
      queuedCount: number;
      droppedCount: number;
      reviewedCount: number;
      confirmedCount: number;
      rejectedCount: number;
      batchCount: number;
      batchSize: number;
      findingCandidateCount: number;
      findingReviewedCount: number;
      findingConfirmedCount: number;
      findingRejectedCount: number;
      findingDroppedCount: number;
      findingBatchCount: number;
    };
  };
}

export interface BurpAnalysisSummary {
  endpointCount: number;
  leakCount: number;
  jsFileCount: number;
}

export interface AnalysisResult {
  success: true;
  url?: string;
  apis: ApiResult[];
  assets: AssetResult[];
  params: ParamResult[];
  auth: string[];
  secrets: SecretResult[];
  risk: RiskResult[];
  findings: FindingResult[];
  groups: FindingGroups;
  meta: AnalysisMeta;
}

export interface LeakResult {
  category: string;
  type: string;
  value?: string;
  severity: Severity;
  confidence?: number;
  source?: string;
  evidence?: string;
}

export interface EndpointResult extends ApiResult {
  evidence?: string;
}

export interface JsFileResult {
  url: string;
  type: AssetResult['type'] | 'webpack-module';
  chunkName?: string;
  source?: string;
  confidence?: number;
  evidence?: string;
}

export interface BurpAnalysisResult {
  success: true;
  url?: string;
  summary: BurpAnalysisSummary;
  leaks: LeakResult[];
  endpoints: EndpointResult[];
  jsFiles: JsFileResult[];
}

export interface AnalysisError {
  success: false;
  error: {
    message: string;
  };
}

export type AnalysisResponse = AnalysisResult | AnalysisError;
export type AnalysisApiResponse = BurpAnalysisResult | AnalysisError;

export interface AnalyzeOptions {
  mode: AnalyzeMode;
}
