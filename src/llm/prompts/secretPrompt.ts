import type { SecretContext } from '../../types/llm.js';

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
