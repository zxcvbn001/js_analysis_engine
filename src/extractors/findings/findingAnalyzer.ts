import * as t from '@babel/types';
import { calleeName } from '../../engine/propagation/stringResolver.js';
import { traverseAst } from '../../engine/traverser/traverseAst.js';
import type { ApiResult, AssetResult, FindingResult, RiskResult, SecretResult, Severity } from '../../types/results.js';
import { uniqueBy } from '../../utils/dedupe.js';

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
  { category: '业务敏感', type: 'phone-id-card-field', severity: 'medium', confidence: 0.7, valuePattern: /(?:phone|mobile|tel|idCard|identity|身份证|手机号)/i, namePattern: /phone|mobile|tel|idCard|identity|certNo|cardNo|身份证|手机号/i },
  { category: '加密逻辑', type: 'crypto-key-iv', severity: 'medium', confidence: 0.75, valuePattern: /(?:AES|RSA|DES|CBC|ECB|PKCS|encrypt|decrypt|publicKey|privateKey|-----BEGIN)/i, namePattern: /aes|rsa|encrypt|decrypt|cryptoKey|aesKey|rsaKey|publicKey|privateKey|(^|_)iv($|_)/i },
  { category: 'SSRF/RCE点', type: 'dynamic-url', severity: 'high', confidence: 0.65, namePattern: /callbackUrl|redirectUrl|targetUrl|url|uri|endpoint|webhook/i },
  { category: 'JWT/OAuth', type: 'jwt-oauth', severity: 'high', confidence: 0.8, valuePattern: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|oauth|client_secret|client_id|authorization_code/i, namePattern: /jwt|oauth|clientSecret|clientId|authorization/i },
  { category: 'GraphQL', type: 'graphql', severity: 'medium', confidence: 0.75, valuePattern: /\/graphql\b|query\s+\w*\s*\{|mutation\s+\w*\s*\{|__schema|gql`/i, namePattern: /graphql|gql|query|mutation/i },
  { category: '路由信息', type: 'sensitive-route', severity: 'medium', confidence: 0.7, valuePattern: /\/(?:admin|debug|internal|manage|system|console|actuator)(?:\/|$|\?)/i, namePattern: /admin|debug|internal|manage|system|console|actuator/i },
];

const callRules: FindingRule[] = [
  { category: 'SSRF/RCE点', type: 'command-execution', severity: 'high', confidence: 0.85, valuePattern: /\b(?:eval|Function|exec|execSync|spawn|spawnSync|system|popen|child_process\.exec|child_process\.spawn)\b/ },
  { category: 'SSRF/RCE点', type: 'dynamic-network-request', severity: 'high', confidence: 0.7, valuePattern: /\b(?:fetch|XMLHttpRequest|axios|request|http\.get|https\.get)\b/ },
  { category: 'GraphQL', type: 'graphql-client-call', severity: 'medium', confidence: 0.75, valuePattern: /\b(?:graphql|gql|ApolloClient|useQuery|useMutation)\b/i },
  { category: '加密逻辑', type: 'crypto-call', severity: 'medium', confidence: 0.75, valuePattern: /\b(?:encrypt|decrypt|createCipher|createDecipher|CryptoJS|JSEncrypt|RSA|AES)\b/i },
];

const MAX_FINDINGS = 1000;
const MAX_EVIDENCE_LINE_CHARS = 500;
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
    if (findings.length >= MAX_FINDINGS) {
      return;
    }
    findings.push(...items.slice(0, MAX_FINDINGS - findings.length).map(normalizeFinding));
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
      if (findings.length >= MAX_FINDINGS) {
        path.stop();
        return;
      }
      const name = t.isIdentifier(path.node.id) ? path.node.id.name : undefined;
      const value = literalText(path.node.init);
      pushFindings(matchRules(value, name, name ? 'identifier' : 'string', contextAround(lines, path.node.loc?.start.line) ?? evidenceOf(name, value)));
    },
    ObjectProperty(path) {
      if (findings.length >= MAX_FINDINGS) {
        path.stop();
        return;
      }
      const name = propertyName(path.node.key);
      const value = literalText(path.node.value);
      pushFindings(matchRules(value, name, name ? 'identifier' : 'string', contextAround(lines, path.node.loc?.start.line) ?? evidenceOf(name, value)));
    },
    StringLiteral(path) {
      if (findings.length >= MAX_FINDINGS) {
        path.stop();
        return;
      }
      pushFindings(matchRules(path.node.value, undefined, 'string', contextAround(lines, path.node.loc?.start.line) ?? path.node.value));
    },
    TemplateElement(path) {
      if (findings.length >= MAX_FINDINGS) {
        path.stop();
        return;
      }
      const value = path.node.value.cooked ?? path.node.value.raw;
      pushFindings(matchRules(value, undefined, 'string', contextAround(lines, path.node.loc?.start.line) ?? value));
    },
    CallExpression(path) {
      if (findings.length >= MAX_FINDINGS) {
        path.stop();
        return;
      }
      const name = calleeName(path.node.callee);
      pushFindings(matchCallRules(name));
      if (isDynamicUrlCall(path.node)) {
        pushFindings([{
          category: 'SSRF/RCE点',
          type: 'dynamic-url',
          severity: 'high',
          confidence: 0.65,
          source: 'call',
          evidence: contextAround(lines, path.node.loc?.start.line) ?? `call:${name}`,
        }]);
      }
    },
  });

  return uniqueBy(findings, (finding) => `${finding.category}:${finding.type}:${finding.value ?? ''}:${finding.evidence ?? ''}`).slice(0, MAX_FINDINGS);
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
    return 'SSRF/RCE点';
  }
  return 'API 信息';
}

function isDynamicUrlCall(node: t.CallExpression): boolean {
  const name = calleeName(node.callee);
  if (!/fetch|axios|request|open/i.test(name)) {
    return false;
  }
  const firstArg = node.arguments[0];
  return Boolean(firstArg && !t.isStringLiteral(firstArg) && !t.isObjectExpression(firstArg));
}

function evidenceForApi(content: string, lines: string[], api: ApiResult): string | undefined {
  const candidates = [api.url, api.resolvedUrl].filter(Boolean) as string[];
  for (const candidate of candidates) {
    const index = content.indexOf(candidate);
    if (index === -1) {
      continue;
    }
    const line = content.slice(0, index).split(/\r?\n/).length;
    return contextAround(lines, line);
  }
  return undefined;
}

function contextAround(lines: string[], line?: number, radius = 2): string | undefined {
  if (!line || lines.length === 0) {
    return undefined;
  }
  const start = Math.max(1, line - radius);
  const end = Math.min(lines.length, line + radius);
  return lines
    .slice(start - 1, end)
    .map((text, index) => `${start + index}: ${trimLine(text)}`)
    .join('\n')
    .slice(0, MAX_EVIDENCE_CHARS);
}

function normalizeFinding(finding: FindingResult): FindingResult {
  return {
    ...finding,
    evidence: finding.evidence ? trimText(finding.evidence, MAX_EVIDENCE_CHARS) : finding.evidence,
    value: finding.value ? trimText(finding.value, 1000) : finding.value,
  };
}

function trimLine(text: string): string {
  return text.length > MAX_EVIDENCE_LINE_CHARS ? `${text.slice(0, MAX_EVIDENCE_LINE_CHARS)}... [truncated ${text.length - MAX_EVIDENCE_LINE_CHARS} chars]` : text;
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
