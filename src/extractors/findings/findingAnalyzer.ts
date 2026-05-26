import * as t from '@babel/types';
import { calleeName } from '../../engine/propagation/stringResolver.js';
import { traverseAst } from '../../engine/traverser/traverseAst.js';
import type { ApiResult, AssetResult, FindingResult, RiskResult, SecretResult, Severity } from '../../types/results.js';
import { uniqueBy } from '../../utils/dedupe.js';
import { buildEvidenceSnippet, contextAroundLines } from '../../utils/evidence.js';

interface FindingRule {
  category: string;
  type: string;
  severity: Severity;
  confidence: number;
  valuePattern?: RegExp;
  namePattern?: RegExp;
}

const stringRules: FindingRule[] = [
  { category: '敏感凭据', type: 'access-key', severity: 'high', confidence: 0.85, valuePattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { category: '敏感凭据', type: 'secret-key', severity: 'high', confidence: 0.75, namePattern: /secret|secretKey|secret_key|sk|access[_-]?key/i },
  { category: '敏感凭据', type: 'token', severity: 'high', confidence: 0.75, valuePattern: /Bearer\s+[A-Za-z0-9._~+/=-]{12,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/i, namePattern: /token|accessToken|refreshToken/i },
  { category: '敏感凭据', type: 'password', severity: 'high', confidence: 0.65, namePattern: /password|passwd|pwd/i },
  { category: 'API 信息', type: 'gateway-or-api-base', severity: 'medium', confidence: 0.7, valuePattern: /(?:gateway|\/api\/|api[-.][A-Za-z0-9.-]+|baseUrl|baseURL)/i, namePattern: /gateway|baseUrl|baseURL|apiHost|apiBase/i },
  { category: 'API 信息', type: 'environment-url', severity: 'medium', confidence: 0.7, valuePattern: /https?:\/\/[^'"`\s]*(?:dev|test|uat|stage|staging|pre|prod)[^'"`\s]*/i, namePattern: /env|environment|profile/i },
  { category: '权限信息', type: 'role-admin-auth', severity: 'medium', confidence: 0.7, valuePattern: /(?:role|admin|auth|permission|privilege|rbac)/i, namePattern: /role|admin|auth|permission|privilege|rbac/i },
  { category: '云配置', type: 'aliyun-oss', severity: 'medium', confidence: 0.8, valuePattern: /oss-[a-z0-9-]+\.aliyuncs\.com|aliyuncs\.com|STS\.AssumeRole|securityToken/i, namePattern: /oss|aliyun|stsToken|securityToken/i },
  { category: '云配置', type: 'aws-s3', severity: 'medium', confidence: 0.8, valuePattern: /s3[.-][a-z0-9-]+\.amazonaws\.com|amazonaws\.com/i, namePattern: /s3|aws|bucket/i },
  { category: '云配置', type: 'tencent-cos', severity: 'medium', confidence: 0.8, valuePattern: /cos\.[a-z0-9-]+\.myqcloud\.com|myqcloud\.com/i, namePattern: /cos|tencent|qcloud/i },
  { category: '第三方配置', type: 'wechat', severity: 'medium', confidence: 0.75, valuePattern: /wx[a-f0-9]{16,}|api\.mch\.weixin\.qq\.com|open\.weixin\.qq\.com/i, namePattern: /wechat|weixin|wxAppId|appId|mchId/i },
  { category: '第三方配置', type: 'aliyun', severity: 'medium', confidence: 0.7, valuePattern: /aliyun|aliyuncs\.com/i, namePattern: /aliyun|ali/i },
  { category: '第三方配置', type: 'tencent-cloud', severity: 'medium', confidence: 0.7, valuePattern: /qcloud|tencentcloud|myqcloud\.com/i, namePattern: /qcloud|tencent/i },
  { category: '调试信息', type: 'source-map', severity: 'medium', confidence: 0.8, valuePattern: /sourceMappingURL=.*\.map|\.js\.map|\.css\.map/i },
  { category: '调试信息', type: 'debug-dev', severity: 'medium', confidence: 0.7, valuePattern: /(?:debug|devtools|sourceMap|__DEV__|localhost|webpackHotUpdate)/i, namePattern: /debug|devtools|sourceMap|__DEV__/i },
  { category: '内网信息', type: 'private-ip-or-host', severity: 'medium', confidence: 0.85, valuePattern: /(?:https?:\/\/)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost|\.local\b|\.corp\b|\.internal\b)/i },
  { category: '路由信息', type: 'dynamic-request-target', severity: 'medium', confidence: 0.55, namePattern: /callbackUrl|redirectUrl|targetUrl|returnUrl|nextUrl|webhook/i },
  { category: 'JWT/OAuth', type: 'jwt-oauth', severity: 'high', confidence: 0.8, valuePattern: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|oauth|client_secret|client_id|authorization_code/i, namePattern: /jwt|oauth|clientSecret|clientId|authorization/i },
  { category: 'GraphQL', type: 'graphql', severity: 'medium', confidence: 0.75, valuePattern: /\/graphql\b|query\s+\w*\s*\{|mutation\s+\w*\s*\{|__schema|gql`/i, namePattern: /graphql|gql|query|mutation/i },
  { category: '路由信息', type: 'sensitive-route', severity: 'medium', confidence: 0.7, valuePattern: /\/(?:admin|debug|internal|manage|system|console|actuator)(?:\/|$|\?)/i, namePattern: /admin|debug|internal|manage|system|console|actuator/i },
];

const callRules: FindingRule[] = [
  { category: 'GraphQL', type: 'graphql-client-call', severity: 'medium', confidence: 0.75, valuePattern: /\b(?:graphql|gql|ApolloClient|useQuery|useMutation)\b/i },
];

const MAX_FINDINGS = 1000;
const MAX_FINDINGS_PER_TYPE = 80;
const MAX_FINDINGS_PER_CATEGORY = 200;
const MAX_EVIDENCE_CHARS = 2500;

export function analyzeFindings(input: {
  ast: t.File;
  content: string;
  apis: ApiResult[];
  assets: AssetResult[];
  secrets: SecretResult[];
  risk: RiskResult[];
}): FindingResult[] {
  const findings: FindingResult[] = [];
  const lines = input.content.split(/\r?\n/);
  const pushFindings = (items: FindingResult[]): void => {
    findings.push(...items.map(normalizeFinding));
  };

  for (const api of input.apis) {
    const apiEvidence = evidenceForApi(input.content, lines, api);
    pushFindings([{
      category: 'API 信息',
      type: 'api-endpoint',
      value: api.resolvedUrl ?? api.url,
      severity: 'medium',
      confidence: api.confidence === 'high' ? 0.9 : api.confidence === 'medium' ? 0.7 : 0.5,
      source: 'api',
      evidence: apiEvidence ?? `${api.method ?? 'GET'} ${api.resolvedUrl ?? api.url}`,
    }]);
    pushFindings(matchRules(api.url, undefined, 'api', api.url));
    if (api.resolvedUrl) {
      pushFindings(matchRules(api.resolvedUrl, undefined, 'api', api.resolvedUrl));
    }
    for (const param of api.params ?? []) {
      pushFindings(matchRules(undefined, param, 'api', `${api.url}:${param}`));
    }
    for (const header of api.headers ?? []) {
      pushFindings(matchRules(undefined, header, 'api', `${api.url}:${header}`));
    }
  }

  for (const asset of input.assets) {
    pushFindings([{
      category: 'webpack模块',
      type: 'hidden-asset',
      value: asset.url,
      severity: 'low',
      confidence: 0.85,
      source: 'asset',
      evidence: asset.source,
    }]);
    pushFindings(matchRules(asset.url, asset.chunkName, 'asset', asset.url));
  }

  for (const secret of input.secrets) {
    pushFindings([{
      category: categoryForSecret(secret.type),
      type: secret.type,
      value: secret.value,
      severity: secret.severity,
      confidence: secret.confidence ?? 0.75,
      source: 'secret',
      evidence: secret.evidence,
    }]);
  }

  for (const risk of input.risk) {
    pushFindings([{
      category: categoryForRisk(risk.type),
      type: risk.type,
      severity: risk.severity,
      confidence: 0.7,
      source: 'risk',
      evidence: risk.evidence,
    }]);
  }

  traverseAst(input.ast, {
    VariableDeclarator(path) {
      if (findings.length >= MAX_FINDINGS * 3) {
        path.stop();
        return;
      }
      const name = t.isIdentifier(path.node.id) ? path.node.id.name : undefined;
      const value = literalText(path.node.init);
      pushFindings(matchRules(
        value,
        name,
        name ? 'identifier' : 'string',
        buildEvidenceSnippet({ content: input.content, value: value ?? name, line: path.node.loc?.start.line, column: path.node.loc?.start.column, maxChars: MAX_EVIDENCE_CHARS })
          ?? evidenceOf(name, value),
      ));
    },
    ObjectProperty(path) {
      if (findings.length >= MAX_FINDINGS * 3) {
        path.stop();
        return;
      }
      const name = propertyName(path.node.key);
      const value = literalText(path.node.value);
      pushFindings(matchRules(
        value,
        name,
        name ? 'identifier' : 'string',
        buildEvidenceSnippet({ content: input.content, value: value ?? name, line: path.node.loc?.start.line, column: path.node.loc?.start.column, maxChars: MAX_EVIDENCE_CHARS })
          ?? evidenceOf(name, value),
      ));
    },
    StringLiteral(path) {
      if (findings.length >= MAX_FINDINGS * 3) {
        path.stop();
        return;
      }
      pushFindings(matchRules(
        path.node.value,
        undefined,
        'string',
        buildEvidenceSnippet({ content: input.content, value: path.node.value, line: path.node.loc?.start.line, column: path.node.loc?.start.column, maxChars: MAX_EVIDENCE_CHARS })
          ?? path.node.value,
      ));
    },
    TemplateElement(path) {
      if (findings.length >= MAX_FINDINGS * 3) {
        path.stop();
        return;
      }
      const value = path.node.value.cooked ?? path.node.value.raw;
      pushFindings(matchRules(
        value,
        undefined,
        'string',
        buildEvidenceSnippet({ content: input.content, value, line: path.node.loc?.start.line, column: path.node.loc?.start.column, maxChars: MAX_EVIDENCE_CHARS })
          ?? value,
      ));
    },
    CallExpression(path) {
      if (findings.length >= MAX_FINDINGS * 3) {
        path.stop();
        return;
      }
      const name = calleeName(path.node.callee);
      pushFindings(matchCallRules(name));
      if (isDynamicExternalRequestCall(path.node)) {
        pushFindings([{
          category: '路由信息',
          type: 'dynamic-request-target',
          severity: 'medium',
          confidence: 0.55,
          source: 'call',
          evidence: buildEvidenceSnippet({ content: input.content, value: name, line: path.node.loc?.start.line, column: path.node.loc?.start.column, maxChars: MAX_EVIDENCE_CHARS })
            ?? `call:${name}`,
        }]);
      }
    },
  });

  return limitFindings(findings);
}

function matchRules(
  value: string | undefined,
  name: string | undefined,
  source: FindingResult['source'],
  evidence?: string,
): FindingResult[] {
  const text = value ?? '';
  return stringRules.flatMap((rule) => {
    const valueMatched = value ? (rule.valuePattern?.test(text) ?? false) : false;
    const nameMatched = name ? (rule.namePattern?.test(name) ?? false) : false;
    if (!valueMatched && !nameMatched) {
      return [];
    }
    if (nameMatched && !valueMatched && value !== undefined && value.length > 0 && isClearlyPlaceholder(value)) {
      return [];
    }
    return [{
      category: rule.category,
      type: rule.type,
      value: value || name,
      severity: rule.severity,
      confidence: rule.confidence,
      source,
      evidence,
    }];
  });
}

function matchCallRules(name: string): FindingResult[] {
  return callRules.flatMap((rule) => {
    if (!(rule.valuePattern?.test(name) ?? false)) {
      return [];
    }
    return [{
      category: rule.category,
      type: rule.type,
      value: name,
      severity: rule.severity,
      confidence: rule.confidence,
      source: 'call',
      evidence: `call:${name}`,
    }];
  });
}

function literalText(node: t.Node | null | undefined): string | undefined {
  if (!node) {
    return undefined;
  }
  if (t.isStringLiteral(node)) {
    return node.value;
  }
  if (t.isTemplateLiteral(node)) {
    return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw).join('${value}');
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

function evidenceOf(name?: string, value?: string): string | undefined {
  if (!name && !value) {
    return undefined;
  }
  if (!name) {
    return value;
  }
  return `${name}=${redact(value ?? '')}`;
}

function categoryForSecret(type: string): string {
  if (/oss|s3|cos|aliyun|aws/i.test(type)) {
    return '云配置';
  }
  if (/jwt|bearer|token|key|secret|password/i.test(type)) {
    return '敏感凭据';
  }
  if (/internal/i.test(type)) {
    return '内网信息';
  }
  if (/debug|test/i.test(type)) {
    return '调试信息';
  }
  return '敏感凭据';
}

function categoryForRisk(type: string): string {
  if (/admin|internal|debug/i.test(type)) {
    return '路由信息';
  }
  if (/destructive/i.test(type)) {
    return '路由信息';
  }
  return 'API 信息';
}

function isDynamicExternalRequestCall(node: t.CallExpression): boolean {
  const name = calleeName(node.callee);
  if (!/fetch|axios|request|open/i.test(name)) {
    return false;
  }
  const firstArg = node.arguments[0];
  if (!firstArg || t.isStringLiteral(firstArg) || t.isObjectExpression(firstArg)) {
    return false;
  }

  const text = expressionText(firstArg);
  return /callback|redirect|returnurl|nexturl|target|webhook|location\.|document\.url|window\.name|searchParams|query/i.test(text);
}

function expressionText(node: t.Node): string {
  if (t.isIdentifier(node)) {
    return node.name;
  }
  if (t.isMemberExpression(node)) {
    return calleeName(node);
  }
  if (t.isCallExpression(node)) {
    return calleeName(node.callee);
  }
  if (t.isTemplateLiteral(node)) {
    return node.quasis.map((quasi) => quasi.value.raw).join('${value}');
  }
  if (t.isBinaryExpression(node)) {
    return `${expressionText(node.left)} ${expressionText(node.right)}`;
  }
  return node.type;
}

function evidenceForApi(content: string, lines: string[], api: ApiResult): string | undefined {
  const candidates = [api.url, api.resolvedUrl].filter(Boolean) as string[];
  for (const candidate of candidates) {
    const index = content.indexOf(candidate);
    if (index === -1) {
      continue;
    }
    const line = content.slice(0, index).split(/\r?\n/).length;
    return buildEvidenceSnippet({ content, value: candidate, line, maxChars: MAX_EVIDENCE_CHARS })
      ?? contextAroundLines(lines, line, 2, MAX_EVIDENCE_CHARS);
  }
  return undefined;
}

function normalizeFinding(finding: FindingResult): FindingResult {
  return {
    ...finding,
    evidence: finding.evidence ? trimText(finding.evidence, MAX_EVIDENCE_CHARS) : finding.evidence,
    value: finding.value ? trimText(finding.value, 1000) : finding.value,
  };
}

function limitFindings(findings: FindingResult[]): FindingResult[] {
  const deduped = uniqueBy(findings, findingIdentity);
  const sorted = deduped.sort(compareFindings);
  const accepted: FindingResult[] = [];
  const perType = new Map<string, number>();
  const perCategory = new Map<string, number>();

  for (const finding of sorted) {
    if (accepted.length >= MAX_FINDINGS) {
      break;
    }

    const typeKey = `${finding.category}:${finding.type}`;
    const typeCount = perType.get(typeKey) ?? 0;
    if (typeCount >= MAX_FINDINGS_PER_TYPE) {
      continue;
    }

    const categoryCount = perCategory.get(finding.category) ?? 0;
    if (categoryCount >= MAX_FINDINGS_PER_CATEGORY) {
      continue;
    }

    accepted.push(finding);
    perType.set(typeKey, typeCount + 1);
    perCategory.set(finding.category, categoryCount + 1);
  }

  return accepted;
}

function findingIdentity(finding: FindingResult): string {
  const value = normalizeValue(finding.value);
  const evidence = normalizeEvidence(finding.evidence);
  if (finding.source === 'identifier' || finding.source === 'string') {
    return `${finding.category}:${finding.type}:${finding.source}:${value}`;
  }
  return `${finding.category}:${finding.type}:${finding.source}:${value}:${evidence}`;
}

function compareFindings(left: FindingResult, right: FindingResult): number {
  const severityDiff = severityScore(right.severity) - severityScore(left.severity);
  if (severityDiff !== 0) {
    return severityDiff;
  }

  const confidenceDiff = right.confidence - left.confidence;
  if (confidenceDiff !== 0) {
    return confidenceDiff;
  }

  const sourceDiff = sourcePriority(left.source) - sourcePriority(right.source);
  if (sourceDiff !== 0) {
    return sourceDiff;
  }

  return (left.value ?? '').localeCompare(right.value ?? '');
}

function severityScore(severity: Severity): number {
  if (severity === 'high') {
    return 3;
  }
  if (severity === 'medium') {
    return 2;
  }
  return 1;
}

function sourcePriority(source: FindingResult['source']): number {
  switch (source) {
    case 'secret':
      return 6;
    case 'api':
      return 5;
    case 'risk':
      return 4;
    case 'call':
      return 3;
    case 'identifier':
      return 2;
    case 'string':
      return 1;
    case 'asset':
      return 0;
    default:
      return 0;
  }
}

function normalizeEvidence(value?: string): string {
  if (!value) {
    return '';
  }
  return value.replace(/\s+/g, ' ').trim().slice(0, 220);
}

function normalizeValue(value?: string): string {
  if (!value) {
    return '';
  }
  return value.trim().slice(0, 220);
}

function trimText(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}... [truncated ${text.length - max} chars]` : text;
}

function redact(value: string): string {
  if (value.length <= 16) {
    return value;
  }
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

function isClearlyPlaceholder(value: string): boolean {
  return /^(xxx+|your[_-]?|example|changeme|password|token|test|demo)$/i.test(value);
}
