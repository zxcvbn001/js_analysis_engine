import type { ApiResult } from '../../types/results.js';
import type { SecretCandidate, SecretContext } from '../../types/llm.js';
import { buildEvidenceSnippet } from '../../utils/evidence.js';

const DEFAULT_RADIUS = 20;
const MAX_CONTEXT_CHARS = 4000;

export function extractSecretContext(content: string, candidate: SecretCandidate, apis: ApiResult[], radius = DEFAULT_RADIUS): SecretContext {
  const lines = content.split(/\r?\n/);
  const line = candidate.line ?? 1;
  const context = buildEvidenceSnippet({
    content,
    value: candidate.value,
    line,
    column: candidate.column,
    lineRadius: radius,
    charRadius: 1200,
    maxChars: MAX_CONTEXT_CHARS,
  }) ?? '';

  const nearbyApis = apis
    .filter((api) => context.includes(api.url))
    .map((api) => `${api.method ?? 'GET'} ${api.url}`);
  const nearbyHeaders = ['Authorization', 'X-Token', 'JWT', 'Bearer'].filter((header) => context.toLowerCase().includes(header.toLowerCase()));

  return {
    candidate,
    context,
    functionName: inferFunctionName(lines, line),
    nearbyApis,
    nearbyHeaders,
  };
}

function inferFunctionName(lines: string[], line: number): string | undefined {
  for (let index = Math.max(0, line - 1); index >= Math.max(0, line - 80); index -= 1) {
    const match = lines[index]?.match(/function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(/);
    const name = match?.[1] ?? match?.[2];
    if (name) {
      return name;
    }
  }
  return undefined;
}
