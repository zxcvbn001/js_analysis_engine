export type Severity = 'low' | 'medium' | 'high';
export type AnalyzeMode = 'fast' | 'full';

export interface ApiResult {
  url: string;
  method?: string;
  params?: string[];
  headers?: string[];
  auth?: string;
  source?: string;
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

export interface AnalysisResult {
  success: true;
  url?: string;
  apis: ApiResult[];
  assets: AssetResult[];
  params: ParamResult[];
  auth: string[];
  secrets: SecretResult[];
  risk: RiskResult[];
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
