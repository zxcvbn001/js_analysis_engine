import type { ApiResult, AssetResult, FindingGroups, FindingResult, SecretResult } from '../../types/results.js';

const exposureCategories = new Set([
  '敏感凭据',
  '权限信息',
  '云配置',
  '第三方配置',
  '调试信息',
  '内网信息',
  '业务敏感',
  '加密逻辑',
  'SSRF/RCE点',
  'JWT/OAuth',
  'GraphQL',
  '路由信息',
]);

const llmConfirmedSecretCategories = new Set(['敏感凭据', '云配置', 'JWT/OAuth']);

export function filterUnconfirmedSensitiveFindings(input: {
  findings: FindingResult[];
  secrets: SecretResult[];
  requireConfirmedSecrets: boolean;
}): FindingResult[] {
  if (!input.requireConfirmedSecrets) {
    return input.findings;
  }

  const confirmedSecretKeys = new Set(input.secrets.map((secret) => `${secret.type}:${secret.value ?? ''}`));
  return input.findings.filter((finding) => {
    if (!llmConfirmedSecretCategories.has(finding.category)) {
      return true;
    }
    return finding.source === 'secret' && confirmedSecretKeys.has(`${finding.type}:${finding.value ?? ''}`);
  });
}

export function groupFindings(input: {
  apis: ApiResult[];
  assets: AssetResult[];
  secrets: SecretResult[];
  findings: FindingResult[];
}): FindingGroups {
  const endpointFindings = input.findings.filter((finding) => finding.source === 'api' || finding.category === 'API 信息');
  const scriptFindings = input.findings.filter((finding) => finding.source === 'asset' || finding.category === 'webpack模块');
  const endpointSet = new Set(endpointFindings);
  const scriptSet = new Set(scriptFindings);
  const confirmedSecretKeys = new Set(input.secrets.map((secret) => `${secret.type}:${secret.value ?? ''}`));
  const exposureFindings = input.findings.filter((finding) => {
    if (!exposureCategories.has(finding.category) || endpointSet.has(finding) || scriptSet.has(finding)) {
      return false;
    }
    if (llmConfirmedSecretCategories.has(finding.category) && finding.source !== 'secret') {
      return false;
    }
    if (finding.source === 'secret') {
      return confirmedSecretKeys.has(`${finding.type}:${finding.value ?? ''}`);
    }
    return true;
  });

  return {
    endpoints: {
      apis: input.apis,
      findings: endpointFindings,
      count: input.apis.length + endpointFindings.length,
    },
    exposures: {
      secrets: input.secrets,
      findings: exposureFindings,
      count: input.secrets.length + exposureFindings.length,
    },
    scripts: {
      assets: input.assets,
      findings: scriptFindings,
      count: input.assets.length + scriptFindings.length,
    },
  };
}
