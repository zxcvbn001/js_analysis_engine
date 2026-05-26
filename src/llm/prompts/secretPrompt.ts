import type { SecretContext, UnifiedReviewContext } from '../../types/llm.js';
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
        value: trimForPrompt(context.finding.value, 500),
        severity: context.finding.severity,
        confidence: context.finding.confidence,
        source: context.finding.source,
        evidence: trimForPrompt(context.finding.evidence, 900),
      })),
    ),
  ].join('\n');
}

export function buildUnifiedReviewPrompt(input: UnifiedReviewContext): string {
  return [
    'You are a JavaScript frontend security analysis expert.',
    'Review secret candidates and security findings together using the shared API/context evidence.',
    'Return JSON only with keys: secrets, findings.',
    'secrets must be an array. Each item: id, is_secret, secret_type, severity, confidence, reason.',
    'findings must be an array. Each item: id, is_risk, category, type, severity, confidence, reason.',
    'Reject false positives. Do not classify normal frontend HTTP calls as SSRF/RCE unless there is evidence of attacker-controlled server-side fetching or dangerous code execution.',
    '',
    'Input:',
    JSON.stringify(toCompactUnifiedPromptPayload(input)),
  ].join('\n');
}

export function toCompactUnifiedPromptPayload(input: UnifiedReviewContext): Record<string, unknown> {
  return {
    apis: input.apis.slice(0, 8).map((api) => ({
      url: trimForPrompt(api.url, 80),
      method: api.method,
      params: api.params?.slice(0, 3),
      headers: api.headers?.slice(0, 3),
    })),
    secrets: input.secrets.map((context) => ({
      id: context.candidate.id,
      type: context.candidate.type,
      value: trimForPrompt(context.candidate.value, 100),
      evidence: trimForPrompt(context.candidate.evidence, 100),
      variableName: context.candidate.variableName,
      nearbyApis: context.nearbyApis.slice(0, 2).map((api) => trimForPrompt(api, 60)),
      nearbyHeaders: context.nearbyHeaders.slice(0, 3),
      context: trimForPrompt(context.context, 160),
    })),
    findings: input.findings.map((context) => ({
      id: context.id,
      category: context.finding.category,
      type: context.finding.type,
      value: trimForPrompt(context.finding.value, 80),
      severity: context.finding.severity,
      confidence: context.finding.confidence,
      source: context.finding.source,
      evidence: trimForPrompt(context.finding.evidence, 100),
    })),
  };
}

function trimForPrompt(value: string | undefined, maxLength: number): string | undefined {
  if (!value) {
    return value;
  }
  return value.length > maxLength ? `${value.slice(0, maxLength)}... [truncated ${value.length - maxLength} chars]` : value;
}
