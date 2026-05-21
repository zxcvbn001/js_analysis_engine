import { describe, expect, it } from 'vitest';
import { analyzeJavaScript } from '../engine/analyzers/javascriptAnalyzer.js';
import { LLMSecretAnalyzer } from '../llm/analyzers/llmSecretAnalyzer.js';
import type { LLMProvider } from '../types/llm.js';

describe('secret detection', () => {
  it('detects contextual secret candidates without regex-only output', async () => {
    const result = await analyzeJavaScript({
      content: `
        const AWS_SECRET_ACCESS_KEY = 'AKIA1234567890ABCDEF';
        const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345';
        const input = "<input type='password'>";
      `,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.secrets.map((secret) => secret.type)).toEqual(expect.arrayContaining(['aws-key', 'bearer-token', 'html-password-input']));
    expect(result.secrets.find((secret) => secret.type === 'aws-key')?.severity).toBe('high');
    expect(result.secrets.find((secret) => secret.type === 'html-password-input')?.severity).toBe('low');
  });

  it('returns evidence with surrounding lines', async () => {
    const result = await analyzeJavaScript({
      content: `
        const beforeOne = true;
        const beforeTwo = true;
        const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345';
        const afterOne = true;
        const afterTwo = true;
      `,
      mode: 'fast',
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    const token = result.secrets.find((secret) => secret.type === 'bearer-token');
    expect(token?.evidence).toContain('beforeTwo');
    expect(token?.evidence).toContain('const token');
    expect(token?.evidence).toContain('afterTwo');

    const apiResult = await analyzeJavaScript({
      content: `
        const beforeOne = true;
        const beforeTwo = true;
        fetch('/api/context-proof');
        const afterOne = true;
        const afterTwo = true;
      `,
      mode: 'fast',
    });

    expect(apiResult.success).toBe(true);
    if (!apiResult.success) {
      return;
    }
    const apiFinding = apiResult.findings.find((finding) => finding.type === 'api-endpoint');
    expect(apiFinding?.evidence).toContain('beforeTwo');
    expect(apiFinding?.evidence).toContain("fetch('/api/context-proof')");
    expect(apiFinding?.evidence).toContain('afterTwo');
  });

  it('truncates evidence for minified single-line bundles', async () => {
    const longLine = `const prefix='${'x'.repeat(20000)}';const token='Bearer abcdefghijklmnopqrstuvwxyz12345';fetch('/api/long-line');`;
    const result = await analyzeJavaScript({
      content: longLine,
      mode: 'fast',
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.findings.length).toBeLessThanOrEqual(1000);
    for (const finding of result.findings) {
      expect(finding.evidence?.length ?? 0).toBeLessThanOrEqual(2600);
    }
    for (const secret of result.secrets) {
      expect(secret.evidence?.length ?? 0).toBeLessThanOrEqual(2600);
    }
  });

  it('classifies security findings across frontend attack surface categories', async () => {
    const result = await analyzeJavaScript({
      content: `
        const accessKeyId = 'AKIA1234567890ABCDEF';
        const ossEndpoint = 'https://oss-cn-shenzhen.aliyuncs.com';
        const wxAppId = 'wx1234567890abcdef';
        const debugUrl = 'https://dev.example.com/debug';
        const intranet = 'http://10.1.2.3/admin';
        const idCardNo = user.identityNo;
        const publicKey = '-----BEGIN PUBLIC KEY-----abc';
        const redirectUrl = query.nextUrl;
        const q = gql\`query User { user { id phone } }\`;
        fetch('/graphql', { method: 'POST', body: q });
        eval(window.name);
      `,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    const categories = result.findings.map((finding) => finding.category);
    expect(categories).toEqual(
      expect.arrayContaining([
        '敏感凭据',
        '云配置',
        '第三方配置',
        '调试信息',
        '内网信息',
        '业务敏感',
        '加密逻辑',
        'SSRF/RCE点',
        'GraphQL',
        '路由信息',
      ]),
    );
    expect(result.findings.some((finding) => finding.type === 'api-endpoint' && finding.value === '/graphql')).toBe(true);
    expect(result.groups.endpoints.apis.some((api) => api.url === '/graphql')).toBe(true);
    expect(result.groups.exposures.findings.length).toBeGreaterThan(0);
    expect(result.groups.scripts.findings.every((finding) => finding.category === 'webpack模块' || finding.source === 'asset')).toBe(true);
  });

  it('filters sensitive findings to LLM-confirmed results in full mode', async () => {
    const provider: LLMProvider = {
      async analyzeSecret(input) {
        const isReal = input.candidate.value.includes('Bearer realtoken');
        return {
          is_secret: isReal,
          secret_type: 'bearer-token',
          severity: 'high',
          confidence: isReal ? 0.95 : 0.1,
          reason: isReal ? 'confirmed token' : 'placeholder false positive',
        };
      },
    };
    const llmAnalyzer = new LLMSecretAnalyzer(provider);
    const result = await analyzeJavaScript({
      content: `
        const realToken = 'Bearer realtokenabcdefghijklmnopqrstuvwxyz';
        const fakeToken = 'Bearer placeholderplaceholder12345';
      `,
      mode: 'full',
      llmAnalyzer,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.secrets).toHaveLength(1);
    expect(result.secrets[0]).toEqual(
      expect.objectContaining({
        type: 'bearer-token',
        source: 'llm+regex',
        confidence: 0.95,
      }),
    );
    expect(result.secrets[0].value).toContain('Bearer realtoken');
    expect(result.findings.filter((finding) => finding.category === '敏感凭据').every((finding) => finding.value?.includes('Bearer realtoken'))).toBe(true);
  });
});
