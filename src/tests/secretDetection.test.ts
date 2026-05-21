import { describe, expect, it } from 'vitest';
import { analyzeJavaScript } from '../engine/analyzers/javascriptAnalyzer.js';

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
  });
});
