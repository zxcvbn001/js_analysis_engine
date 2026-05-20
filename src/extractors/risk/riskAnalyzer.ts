import * as t from '@babel/types';
import type { ApiResult, RiskResult, Severity } from '../../types/results.js';
import { calleeName } from '../../engine/propagation/stringResolver.js';
import { uniqueBy } from '../../utils/dedupe.js';
import { traverseAst } from '../../engine/traverser/traverseAst.js';

const riskTerms: Array<{ term: string; type: string; severity: Severity }> = [
  { term: 'admin', type: 'admin-api', severity: 'high' },
  { term: 'internal', type: 'internal-api', severity: 'high' },
  { term: 'debug', type: 'debug-endpoint', severity: 'medium' },
  { term: 'delete', type: 'destructive-api', severity: 'high' },
  { term: 'export', type: 'export-api', severity: 'medium' },
];

export function analyzeRisks(ast: t.File, apis: ApiResult[]): RiskResult[] {
  const risks: RiskResult[] = [];

  for (const api of apis) {
    risks.push(...scanText(api.url, api.url));
  }

  traverseAst(ast, {
    FunctionDeclaration(path) {
      if (path.node.id) {
        risks.push(...scanText(path.node.id.name, `function:${path.node.id.name}`));
      }
    },
    VariableDeclarator(path) {
      if (t.isIdentifier(path.node.id)) {
        risks.push(...scanText(path.node.id.name, `variable:${path.node.id.name}`));
      }
    },
    CallExpression(path) {
      risks.push(...scanText(calleeName(path.node.callee), `call:${calleeName(path.node.callee)}`));
    },
  });

  return uniqueBy(risks, (risk) => `${risk.type}:${risk.evidence ?? ''}`);
}

function scanText(text: string, evidence: string): RiskResult[] {
  const lower = text.toLowerCase();
  return riskTerms
    .filter((risk) => lower.includes(risk.term))
    .map((risk) => ({ type: risk.type, severity: risk.severity, evidence }));
}
