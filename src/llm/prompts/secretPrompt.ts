import type { SecretContext } from '../../types/llm.js';
import type { FindingReviewContext } from '../../types/llm.js';

export function buildSecretPrompt(input: SecretContext): string {
  return [
    'You are a JavaScript security analysis expert.',
    'Decide whether the candidate is a real sensitive information exposure.',
    'Return JSON only with keys: is_secret, secret_type, severity, confidence, reason.',
    '',
    'Code context:',
    input.context,
    '',
    'Candidate:',
    JSON.stringify(
      {
        type: input.candidate.type,
        value: input.candidate.value,
        evidence: input.candidate.evidence,
        variableName: input.candidate.variableName,
        functionName: input.functionName,
        nearbyApis: input.nearbyApis,
        nearbyHeaders: input.nearbyHeaders,
      },
      null,
      2,
    ),
  ].join('\n');
}

export function buildSecretBatchPrompt(input: SecretContext[]): string {
  return [
    'You are a JavaScript security analysis expert.',
    'Decide whether each candidate is a real sensitive information exposure.',
    'Return JSON only with key: results.',
    'results must be an array. Each item must contain: id, is_secret, secret_type, severity, confidence, reason.',
    '',
    'Candidates:',
    JSON.stringify(
      input.map((context) => ({
        id: context.candidate.id,
        type: context.candidate.type,
        value: context.candidate.value,
        evidence: context.candidate.evidence,
        variableName: context.candidate.variableName,
        functionName: context.functionName,
        nearbyApis: context.nearbyApis,
        nearbyHeaders: context.nearbyHeaders,
        context: context.context,
      })),
      null,
      2,
    ),
  ].join('\n');
}

export function buildFindingBatchPrompt(input: FindingReviewContext[]): string {
  return [
    'You are a JavaScript security analysis expert.',
    'Review each finding and decide whether it is truly the claimed security risk category/type.',
    'Return JSON only with key: results.',
    'results must be an array. Each item must contain: id, is_risk, category, type, severity, confidence, reason.',
    'If a finding is a false positive or does not match the claimed risk category/type, set is_risk=false.',
    '',
    'Findings:',
    JSON.stringify(
      input.map((context) => ({
        id: context.id,
        category: context.finding.category,
        type: context.finding.type,
        value: context.finding.value,
        severity: context.finding.severity,
        confidence: context.finding.confidence,
        source: context.finding.source,
        evidence: context.finding.evidence,
      })),
      null,
      2,
    ),
  ].join('\n');
}
