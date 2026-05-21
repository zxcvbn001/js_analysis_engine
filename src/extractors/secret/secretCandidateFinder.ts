import * as t from '@babel/types';
import type { SecretCandidate } from '../../types/llm.js';
import type { Severity } from '../../types/results.js';
import { sha256 } from '../../utils/hash.js';
import { traverseAst } from '../../engine/traverser/traverseAst.js';

interface PatternRule {
  type: string;
  severity: Severity;
  valuePattern?: RegExp;
  namePattern?: RegExp;
}

const rules: PatternRule[] = [
  { type: 'jwt', severity: 'high', valuePattern: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  { type: 'aws-key', severity: 'high', valuePattern: /AKIA[0-9A-Z]{16}/, namePattern: /aws|secret_access_key/i },
  { type: 'bearer-token', severity: 'high', valuePattern: /Bearer\s+[A-Za-z0-9._~+/=-]{12,}/i },
  { type: 'firebase', severity: 'medium', valuePattern: /firebaseio\.com|firebaseapp\.com|AIza[0-9A-Za-z_-]{20,}/i },
  { type: 'smtp', severity: 'medium', valuePattern: /smtp\.[A-Za-z0-9.-]+/i, namePattern: /smtp|mail/i },
  { type: 'oss', severity: 'medium', valuePattern: /oss-[a-z0-9-]+\.aliyuncs\.com|aliyuncs\.com/i, namePattern: /oss|aliyun/i },
  { type: 'internal-url', severity: 'medium', valuePattern: /https?:\/\/(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.0\.1|localhost)/i },
  { type: 'debug-endpoint', severity: 'medium', valuePattern: /\/(?:debug|devtools|__debug|actuator)(?:\/|$|\?)/i, namePattern: /debug/i },
  { type: 'test-environment', severity: 'low', valuePattern: /https?:\/\/[^'"]*(?:test|staging|uat|dev)[^'"]*/i, namePattern: /test|staging|uat|dev/i },
  { type: 'generic-secret', severity: 'medium', namePattern: /secret|token|password|passwd|api[_-]?key|access[_-]?key/i },
];

const lowRiskHtmlPattern = /<input\b[^>]*type=["']?password/i;

export function findSecretCandidates(ast: t.File, content?: string): SecretCandidate[] {
  const candidates: SecretCandidate[] = [];
  const lines = content?.split(/\r?\n/) ?? [];

  traverseAst(ast, {
    VariableDeclarator(path) {
      const variableName = t.isIdentifier(path.node.id) ? path.node.id.name : undefined;
      if (!path.node.init) {
        return;
      }

      const value = literalValue(path.node.init);
      const line = path.node.loc?.start.line;
      candidates.push(...matchCandidate(value, variableName, line, path.node.loc?.start.column, contextAround(lines, line)));
    },
    ObjectProperty(path) {
      const variableName = propertyName(path.node.key);
      const value = literalValue(path.node.value);
      const line = path.node.loc?.start.line;
      candidates.push(...matchCandidate(value, variableName, line, path.node.loc?.start.column, contextAround(lines, line)));
    },
    StringLiteral(path) {
      const line = path.node.loc?.start.line;
      candidates.push(...matchCandidate(path.node.value, undefined, line, path.node.loc?.start.column, contextAround(lines, line)));
    },
    TemplateElement(path) {
      const value = path.node.value.cooked ?? path.node.value.raw;
      const line = path.node.loc?.start.line;
      candidates.push(...matchCandidate(value, undefined, line, path.node.loc?.start.column, contextAround(lines, line)));
    },
  });

  const seen = new Set<string>();
  return candidates.filter((candidate) => {
    if (seen.has(candidate.id)) {
      return false;
    }
    seen.add(candidate.id);
    return true;
  });
}

function matchCandidate(value: string | undefined, variableName?: string, line?: number, column?: number, context?: string): SecretCandidate[] {
  if (!value && !variableName) {
    return [];
  }

  const text = value ?? '';
  if (lowRiskHtmlPattern.test(text)) {
    return [buildCandidate('html-password-input', 'low', text, 'Password input field, not a hardcoded credential.', line, column, variableName, context)];
  }

  const matches: SecretCandidate[] = [];
  for (const rule of rules) {
    const valueMatched = rule.valuePattern?.test(text) ?? false;
    const nameMatched = variableName ? (rule.namePattern?.test(variableName) ?? false) : false;

    if (!valueMatched && !nameMatched) {
      continue;
    }

    if (nameMatched && !valueMatched && (!value || value.length < 8 || isClearlyPlaceholder(value))) {
      continue;
    }

    matches.push(buildCandidate(rule.type, rule.severity, text || (variableName ?? ''), `${variableName ?? 'literal'}=${redact(text)}`, line, column, variableName, context));
  }

  return matches;
}

function buildCandidate(
  type: string,
  severity: Severity,
  value: string,
  evidence: string,
  line?: number,
  column?: number,
  variableName?: string,
  context?: string,
): SecretCandidate {
  return {
    id: sha256(`${type}:${value}:${line ?? 0}:${column ?? 0}:${variableName ?? ''}`),
    type,
    value,
    severity,
    evidence,
    line,
    column,
    variableName,
    context,
  };
}

function literalValue(node: t.Node): string | undefined {
  if (t.isStringLiteral(node)) {
    return node.value;
  }
  if (t.isTemplateLiteral(node) && node.expressions.length === 0) {
    return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join('');
  }
  return undefined;
}

function propertyName(node: t.Node): string | undefined {
  if (t.isIdentifier(node)) {
    return node.name;
  }
  if (t.isStringLiteral(node) || t.isNumericLiteral(node)) {
    return String(node.value);
  }
  return undefined;
}

function redact(value: string | undefined): string {
  if (!value) {
    return '';
  }
  if (value.length <= 12) {
    return value;
  }
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

function isClearlyPlaceholder(value: string): boolean {
  return /^(xxx+|your[_-]?|example|changeme|password|token)$/i.test(value);
}

function contextAround(lines: string[], line?: number, radius = 2): string | undefined {
  if (!line || lines.length === 0) {
    return undefined;
  }
  const start = Math.max(1, line - radius);
  const end = Math.min(lines.length, line + radius);
  return lines
    .slice(start - 1, end)
    .map((text, index) => `${start + index}: ${text}`)
    .join('\n');
}
