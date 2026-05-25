import type { FindingResult, Severity } from './results.js';

export interface SecretCandidate {
  id: string;
  type: string;
  value: string;
  severity: Severity;
  evidence: string;
  line?: number;
  column?: number;
  variableName?: string;
  context?: string;
}

export interface SecretContext {
  candidate: SecretCandidate;
  context: string;
  functionName?: string;
  nearbyApis: string[];
  nearbyHeaders: string[];
}

export interface LLMSecretResult {
  is_secret: boolean;
  secret_type: string;
  severity: Severity;
  confidence: number;
  reason: string;
}

export interface LLMSecretBatchResult extends LLMSecretResult {
  id: string;
}

export interface FindingReviewContext {
  id: string;
  finding: FindingResult;
}

export interface LLMFindingReviewResult {
  id: string;
  is_risk: boolean;
  category: string;
  type: string;
  severity: Severity;
  confidence: number;
  reason: string;
}

export interface LLMProvider {
  analyzeSecret(input: SecretContext): Promise<LLMSecretResult>;
  analyzeSecretsBatch?(input: SecretContext[]): Promise<LLMSecretBatchResult[]>;
  analyzeFindingsBatch?(input: FindingReviewContext[]): Promise<LLMFindingReviewResult[]>;
}
