import type { LLMSecretAnalyzer } from '../../llm/analyzers/llmSecretAnalyzer.js';
import type { SecretContext } from '../../types/llm.js';
import type { AnalyzeMode, ApiResult, SecretResult } from '../../types/results.js';
import { uniqueBy } from '../../utils/dedupe.js';
import { extractSecretContext } from './contextExtractor.js';
import { findSecretCandidates } from './secretCandidateFinder.js';
import type * as t from '@babel/types';

export interface SecretAnalysisOutput {
  secrets: SecretResult[];
  contexts: SecretContext[];
  llm: {
    enabled: boolean;
    candidateCount: number;
    queuedCount: number;
    droppedCount: number;
    reviewedCount: number;
    confirmedCount: number;
    rejectedCount: number;
  };
}

export async function analyzeSecrets(
  ast: t.File,
  content: string,
  apis: ApiResult[],
  mode: AnalyzeMode,
  llmAnalyzer?: LLMSecretAnalyzer,
): Promise<SecretAnalysisOutput> {
  const candidates = findSecretCandidates(ast, content);
  const contexts = candidates.map((candidate) => extractSecretContext(content, candidate, apis));
  const secrets: SecretResult[] = [];
  let queuedCount = 0;
  let droppedCount = 0;
  let reviewedCount = 0;
  let confirmedCount = 0;
  let rejectedCount = 0;

  for (const context of contexts) {
    const fallback: SecretResult = {
      type: context.candidate.type,
      value: context.candidate.value,
      severity: context.candidate.severity,
      confidence: context.candidate.type === 'html-password-input' ? 0.35 : 0.75,
      source: 'regex',
      evidence: context.candidate.context ?? context.candidate.evidence,
    };

    if (mode === 'full' && llmAnalyzer?.isEnabled()) {
      try {
        const llm = await llmAnalyzer.analyzeNow(context);
        reviewedCount += 1;
        if (llm?.is_secret) {
          confirmedCount += 1;
          secrets.push(llmAnalyzer.toSecretResult(fallback, llm));
        } else {
          rejectedCount += 1;
        }
      } catch {
        reviewedCount += 1;
        droppedCount += 1;
      }
      continue;
    }

    secrets.push(fallback);
  }

  return {
    secrets: uniqueBy(secrets, (secret) => `${secret.type}:${secret.value ?? ''}:${secret.evidence ?? ''}`),
    contexts,
    llm: {
      enabled: Boolean(llmAnalyzer?.isEnabled()),
      candidateCount: candidates.length,
      queuedCount,
      droppedCount,
      reviewedCount,
      confirmedCount,
      rejectedCount,
    },
  };
}
