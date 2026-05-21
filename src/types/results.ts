export type Severity = 'low' | 'medium' | 'high';
export type AnalyzeMode = 'fast' | 'full';

export interface ApiResult {
  url: string;
  resolvedUrl?: string;
  baseUrl?: string;
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
  source: 'api' | 'asset' | 'string' | 'identifier' | 'call' | 'secret' | 'risk';
  evidence?: string;
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
    };
  };
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

export interface AnalysisError {
  success: false;
  error: {
    message: string;
  };
}

export type AnalysisResponse = AnalysisResult | AnalysisError;

export interface AnalyzeOptions {
  mode: AnalyzeMode;
}
