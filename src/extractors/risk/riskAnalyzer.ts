import * as t from '@babel/types';
import type { ApiResult, RiskResult, Severity } from '../../types/results.js';
import { calleeName } from '../../engine/propagation/stringResolver.js';
import { uniqueBy } from '../../utils/dedupe.js';
import { traverseAst } from '../../engine/traverser/traverseAst.js';

const riskTerms: Array<{ pattern: RegExp; type: string; severity: Severity; scope: 'api' | 'identifier' | 'call' }> = [
  { pattern: /\/(?:admin|manage|system|console)(?:\/|$|\?)/i, type: 'admin-api', severity: 'medium', scope: 'api' },
  { pattern: /\/(?:internal|private|actuator)(?:\/|$|\?)/i, type: 'internal-api', severity: 'medium', scope: 'api' },
  { pattern: /\/(?:debug|__debug|devtools)(?:\/|$|\?)/i, type: 'debug-endpoint', severity: 'medium', scope: 'api' },
  { pattern: /\/(?:delete|remove|destroy|drop|truncate)(?:[A-Z/?_-]|$)/i, type: 'destructive-api', severity: 'medium', scope: 'api' },
  { pattern: /\/(?:export|download)(?:[A-Z/?_-]|$)/i, type: 'export-api', severity: 'medium', scope: 'api' },
];

export function analyzeRisks(ast: t.File, apis: ApiResult[]): RiskResult[] {
  const risks: RiskResult[] = [];

  for (const api of apis) {
    risks.push(...scanText(api.url, api.url, 'api'));
  }

  traverseAst(ast, {
    FunctionDeclaration(path) {
      if (path.node.id) {
        risks.push(...scanText(path.node.id.name, `function:${path.node.id.name}`, 'identifier'));
      }
    },
    VariableDeclarator(path) {
      if (t.isIdentifier(path.node.id)) {
        risks.push(...scanText(path.node.id.name, `variable:${path.node.id.name}`, 'identifier'));
      }
    },
    CallExpression(path) {
      risks.push(...scanText(calleeName(path.node.callee), `call:${calleeName(path.node.callee)}`, 'call'));
    },
  });

  return uniqueBy(risks, (risk) => `${risk.type}:${risk.evidence ?? ''}`);
}

function scanText(text: string, evidence: string, scope: 'api' | 'identifier' | 'call'): RiskResult[] {
  return riskTerms
    .filter((risk) => risk.scope === scope && risk.pattern.test(text))
    .map((risk) => ({ type: risk.type, severity: risk.severity, evidence }));
}
