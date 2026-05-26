import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as appConfig from '../config/appConfig.js';
import { configureFileLogger } from '../utils/logger.js';
import { analyzeJavaScript } from '../engine/analyzers/javascriptAnalyzer.js';
import { LLMSecretAnalyzer } from '../llm/analyzers/llmSecretAnalyzer.js';
import { LLMUnifiedAnalyzer } from '../llm/analyzers/llmUnifiedAnalyzer.js';
import type { LLMProvider } from '../types/llm.js';
import { DeepSeekProvider } from '../llm/providers/deepSeekProvider.js';

describe('secret detection', () => {
  afterEach(() => {
    configureFileLogger({ fileEnabled: false, directory: 'logs', level: 'info' });
    rmSync(join(process.cwd(), 'tmp-test-llm-logs'), { recursive: true, force: true });
  });

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

  it('keeps matched secret values visible in evidence for minified single-line bundles', async () => {
    const longLine = `const prefix='${'x'.repeat(9000)}';const password='admin123456';const suffix='${'y'.repeat(9000)}';`;
    const result = await analyzeJavaScript({
      content: longLine,
      mode: 'fast',
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    const secret = result.secrets.find((item) => item.value === 'admin123456');
    expect(secret).toBeTruthy();
    expect(secret?.evidence).toContain('admin123456');
  });

  it('keeps matched api values visible in evidence for minified single-line bundles', async () => {
    const longLine = `const prefix='${'x'.repeat(9000)}';fetch('/api/minified-evidence');const suffix='${'y'.repeat(9000)}';`;
    const result = await analyzeJavaScript({
      content: longLine,
      mode: 'fast',
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    const finding = result.findings.find((item) => item.type === 'api-endpoint' && item.value === '/api/minified-evidence');
    expect(finding).toBeTruthy();
    expect(finding?.evidence).toContain('/api/minified-evidence');
  });

  it('does not classify validation message templates as SMTP secrets', async () => {
    const result = await analyzeJavaScript({
      content: `
        const emailMessage = '%s is not a valid %s';
        const mailError = 'email is not a valid email';
        const smtpHost = 'smtp.example.com';
      `,
      mode: 'fast',
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.secrets.some((secret) => secret.type === 'smtp' && secret.value === '%s is not a valid %s')).toBe(false);
    expect(result.secrets.some((secret) => secret.type === 'smtp' && secret.value === 'email is not a valid email')).toBe(false);
    expect(result.secrets).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'smtp', value: 'smtp.example.com' }),
    ]));
  });

  it('classifies security findings across supported frontend attack surface categories', async () => {
    const result = await analyzeJavaScript({
      content: `
        const accessKeyId = 'AKIA1234567890ABCDEF';
        const ossEndpoint = 'https://oss-cn-shenzhen.aliyuncs.com';
        const wxAppId = 'wx1234567890abcdef';
        const debugUrl = 'https://dev.example.com/debug';
        const intranet = 'http://10.1.2.3/admin';
        const redirectUrl = query.nextUrl;
        const q = gql\`query User { user { id phone } }\`;
        fetch('/graphql', { method: 'POST', body: q });
        fetch(redirectUrl);
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
        'GraphQL',
        '路由信息',
      ]),
    );
    expect(categories).not.toEqual(expect.arrayContaining(['业务敏感', '加密逻辑', 'SSRF/RCE点']));
    expect(result.findings.some((finding) => finding.type === 'api-endpoint' && finding.value === '/graphql')).toBe(true);
    expect(result.groups.endpoints.apis.some((api) => api.url === '/graphql')).toBe(true);
    expect(result.groups.exposures.findings.length).toBeGreaterThan(0);
    expect(result.groups.scripts.findings.every((finding) => finding.category === 'webpack模块' || finding.source === 'asset')).toBe(true);
  });

  it('prioritizes high severity findings and deduplicates noisy results', async () => {
    const repeated = Array.from({ length: 250 }, (_, index) => `const adminPath${index} = '/admin/panel';`).join('\n');
    const result = await analyzeJavaScript({
      content: `
        ${repeated}
        const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345';
        const aws = 'AKIA1234567890ABCDEF';
        fetch('/api/critical/deleteUser');
      `,
      mode: 'fast',
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.findings.length).toBeLessThanOrEqual(1000);
    expect(result.findings.some((finding) => finding.severity === 'high' && finding.type === 'token')).toBe(true);
    expect(result.findings.some((finding) => finding.type === 'access-key')).toBe(true);

    const adminRouteFindings = result.findings.filter((finding) => finding.type === 'sensitive-route' && finding.value === '/admin/panel');
    expect(adminRouteFindings.length).toBeLessThan(20);
  });

  it('does not classify normal frontend HTTP clients as SSRF/RCE', async () => {
    const result = await analyzeJavaScript({
      content: `
        fetch('/api/user');
        axios.post('/api/order/deletePreview', { id });
        const serviceUrl = '/api/service';
        request({ url: serviceUrl, method: 'get' });
        const adminLabel = 'admin user';
      `,
      mode: 'fast',
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.findings.some((finding) => finding.category === 'SSRF/RCE点')).toBe(false);
    expect(result.risk.some((risk) => risk.type === 'admin-api' && risk.evidence === 'variable:adminLabel')).toBe(false);
  });

  it('flags frontend-controllable dynamic request targets without calling them SSRF/RCE', async () => {
    const result = await analyzeJavaScript({
      content: `
        const redirectUrl = new URLSearchParams(location.search).get('next');
        fetch(redirectUrl);
      `,
      mode: 'fast',
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: '路由信息',
          type: 'dynamic-request-target',
          severity: 'medium',
        }),
      ]),
    );
    expect(result.findings.some((finding) => finding.category === 'SSRF/RCE点')).toBe(false);
  });

  it('filters sensitive findings to LLM-confirmed results in full mode', async () => {
    const batchSizes: number[] = [];
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
      async analyzeSecretsBatch(input) {
        batchSizes.push(input.length);
        return input.map((context) => {
          const isReal = context.candidate.value.includes('Bearer realtoken');
          return {
            id: context.candidate.id,
            is_secret: isReal,
            secret_type: 'bearer-token',
            severity: 'high' as const,
            confidence: isReal ? 0.95 : 0.1,
            reason: isReal ? 'confirmed token' : 'placeholder false positive',
          };
        });
      },
      async analyzeUnifiedBatch(input) {
        batchSizes.push(input.secrets.length);
        return {
          secrets: input.secrets.map((context) => {
            const isReal = context.candidate.value.includes('Bearer realtoken');
            return {
              id: context.candidate.id,
              is_secret: isReal,
              secret_type: 'bearer-token',
              severity: 'high' as const,
              confidence: isReal ? 0.95 : 0.1,
              reason: isReal ? 'confirmed token' : 'placeholder false positive',
            };
          }),
          findings: input.findings.map((context) => ({
            id: context.id,
            is_risk: context.finding.value?.includes('Bearer realtoken') || context.finding.type === 'api-endpoint',
            category: context.finding.category,
            type: context.finding.type,
            severity: context.finding.severity,
            confidence: context.finding.value?.includes('Bearer realtoken') ? 0.95 : 0.5,
            reason: 'unified finding review',
          })),
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
      unifiedLlmAnalyzer: new LLMUnifiedAnalyzer(provider),
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
    expect(batchSizes).toEqual([2]);
    expect(result.meta.analysis.llm).toEqual(
      expect.objectContaining({
        enabled: true,
        candidateCount: 2,
        reviewedCount: 2,
        confirmedCount: 1,
        rejectedCount: 1,
        batchCount: 1,
        batchSize: 10,
      }),
    );
  });

  it('reviews LLM secrets in batches of ten', async () => {
    const batchSizes: number[] = [];
    const provider: LLMProvider = {
      async analyzeSecret() {
        throw new Error('single candidate path should not be used');
      },
      async analyzeSecretsBatch(input) {
        batchSizes.push(input.length);
        return input.map((context) => ({
          id: context.candidate.id,
          is_secret: false,
          secret_type: 'token',
          severity: 'low' as const,
          confidence: 0.1,
          reason: 'test false positive',
        }));
      },
      async analyzeUnifiedBatch(input) {
        batchSizes.push(input.secrets.length);
        return {
          secrets: input.secrets.map((context) => ({
            id: context.candidate.id,
            is_secret: false,
            secret_type: 'token',
            severity: 'low' as const,
            confidence: 0.1,
            reason: 'test false positive',
          })),
          findings: input.findings.map((context) => ({
            id: context.id,
            is_risk: false,
            category: context.finding.category,
            type: context.finding.type,
            severity: 'low' as const,
            confidence: 0.1,
            reason: 'test false positive',
          })),
        };
      },
    };
    const content = Array.from({ length: 23 }, (_, index) => `const token${index} = 'Bearer tokenvalue${index}abcdefghijklmnop';`).join('\n');
    const result = await analyzeJavaScript({
      content,
      mode: 'full',
      llmAnalyzer: new LLMSecretAnalyzer(provider),
      unifiedLlmAnalyzer: new LLMUnifiedAnalyzer(provider),
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(batchSizes.slice(0, 5)).toEqual([5, 5, 5, 5, 3]);
    expect(batchSizes.reduce((sum, size) => sum + size, 0)).toBe(23);
    expect(result.secrets).toHaveLength(0);
    expect(result.meta.analysis.llm.reviewedCount).toBe(23);
    expect(result.meta.analysis.llm.rejectedCount).toBe(23);
    expect(result.meta.analysis.llm.batchCount).toBe(5);
  });

  it('writes detailed LLM review logs in full mode', async () => {
    configureFileLogger({ fileEnabled: true, directory: 'tmp-test-llm-logs', level: 'info' });
    const provider: LLMProvider = {
      async analyzeSecret() {
        throw new Error('single candidate path should not be used');
      },
      async analyzeSecretsBatch(input) {
        return input.map((context) => ({
          id: context.candidate.id,
          is_secret: true,
          secret_type: context.candidate.type,
          severity: 'high' as const,
          confidence: 0.9,
          reason: 'confirmed by test provider',
        }));
      },
      async analyzeUnifiedBatch(input) {
        return {
          secrets: input.secrets.map((context) => ({
            id: context.candidate.id,
            is_secret: true,
            secret_type: context.candidate.type,
            severity: 'high' as const,
            confidence: 0.9,
            reason: 'confirmed by test provider',
          })),
          findings: input.findings.map((context) => ({
            id: context.id,
            is_risk: true,
            category: context.finding.category,
            type: context.finding.type,
            severity: context.finding.severity,
            confidence: 0.9,
            reason: 'confirmed by test provider',
          })),
        };
      },
    };

    const result = await analyzeJavaScript({
      content: "const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345';",
      mode: 'full',
      llmAnalyzer: new LLMSecretAnalyzer(provider),
      unifiedLlmAnalyzer: new LLMUnifiedAnalyzer(provider),
    });

    expect(result.success).toBe(true);
    const logFile = join(process.cwd(), 'tmp-test-llm-logs', `${new Date().toISOString().slice(0, 10)}.log`);
    const logText = readFileSync(logFile, 'utf8');
    expect(logText).toContain('llm_unified_review_decision');
    expect(logText).toContain('llm_unified_batch_start');
    expect(logText).toContain('llm_unified_batch_completed');
    expect(logText).toContain('llm_analysis_summary');
    expect(logText).toContain('secretCandidateCount');
    expect(logText).toContain('findingCandidateCount');
    expect(logText).toContain('secretIds');
    expect(logText).toContain('findingIds');
  });

  it('logs why LLM review is not requested', async () => {
    configureFileLogger({ fileEnabled: true, directory: 'tmp-test-llm-logs', level: 'info' });

    const result = await analyzeJavaScript({
      content: "fetch('/api/no-secret-candidates')",
      mode: 'full',
      llmAnalyzer: new LLMSecretAnalyzer({
        async analyzeSecret() {
          throw new Error('should not be called');
        },
        async analyzeSecretsBatch() {
          throw new Error('should not be called');
        },
      }),
    });

    expect(result.success).toBe(true);
    const logFile = join(process.cwd(), 'tmp-test-llm-logs', `${new Date().toISOString().slice(0, 10)}.log`);
    const logText = readFileSync(logFile, 'utf8');
    expect(logText).toContain('analyze_js_llm_runtime');
    expect(logText).toContain('llm_unified_review_decision');
    expect(logText).toContain('llm_unified_review_not_requested');
    expect(logText).toContain('llm provider is not configured');
  });

  it('writes detailed provider prompt and response logs with redaction', async () => {
    configureFileLogger({ fileEnabled: true, directory: 'tmp-test-llm-logs', level: 'info' });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(
      JSON.stringify({
        choices: [{
          message: {
            content: JSON.stringify({
              results: [{
                id: 'unused',
                is_secret: true,
                secret_type: 'bearer-token',
                severity: 'high',
                confidence: 0.9,
                reason: 'confirmed',
              }],
            }),
          },
        }],
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );

    try {
      const provider = new DeepSeekProvider({
        apiKey: 'test-key',
        baseUrl: 'https://llm.example',
        model: 'deepseek-test',
        timeoutMs: 8000,
        logPrompts: true,
        logResponses: true,
        logRawPayloads: false,
      });

      await provider.analyzeSecretsBatch([{
        candidate: {
          id: 'candidate-1',
          type: 'bearer-token',
          value: 'Bearer abcdefghijklmnopqrstuvwxyz12345',
          severity: 'high',
          evidence: 'token=Bearer abcdefghijklmnopqrstuvwxyz12345',
        },
        context: "const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345';",
        nearbyApis: ['/api/user'],
        nearbyHeaders: ['Authorization'],
      }]);
    } finally {
      globalThis.fetch = originalFetch;
    }

    const logFile = join(process.cwd(), 'tmp-test-llm-logs', `${new Date().toISOString().slice(0, 10)}.log`);
    const logText = readFileSync(logFile, 'utf8');
    expect(logText).toContain('llm_provider_prompt_built');
    expect(logText).toContain('llm_provider_request_start');
    expect(logText).toContain('llm_provider_response_body_received');
    expect(logText).toContain('llm_provider_response_parsed');
    expect(logText).toContain('[INFO]');
    expect(logText).toContain('promptPreview');
    expect(logText).toContain('responsePreview');
    expect(logText).toContain('Bearer [REDACTED]');
    expect(logText).not.toContain('Bearer abcdefghijklmnopqrstuvwxyz12345');
  });

  it('keeps unified review prompts compact enough for batch review', async () => {
    configureFileLogger({ fileEnabled: true, directory: 'tmp-test-llm-logs', level: 'info' });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(
      JSON.stringify({
        choices: [{
          message: {
            content: JSON.stringify({
              secrets: [],
              findings: [],
            }),
          },
        }],
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );

    try {
      const provider = new DeepSeekProvider({
        apiKey: 'test-key',
        baseUrl: 'https://llm.example',
        model: 'deepseek-test',
        timeoutMs: 8000,
        logPrompts: true,
        logResponses: true,
        logRawPayloads: false,
      });

      await provider.analyzeUnifiedBatch({
        apis: Array.from({ length: 40 }, (_, index) => ({
          url: `/api/${index}/${'x'.repeat(100)}`,
          method: 'POST',
          params: ['a', 'b', 'c', 'd', 'e', 'f', 'g'],
          headers: ['Authorization', 'X-Test', 'X-Trace', 'X-Api-Key', 'X-Role', 'X-Env', 'X-Flag'],
        })),
        secrets: [{
          candidate: {
            id: 'secret-1',
            type: 'bearer-token',
            value: `Bearer ${'a'.repeat(120)}`,
            severity: 'high',
            evidence: `const token='Bearer ${'a'.repeat(300)}';`,
          },
          context: `const token='Bearer ${'a'.repeat(3000)}';`,
          nearbyApis: ['/api/user', '/api/admin', '/api/order', '/api/audit', '/api/export'],
          nearbyHeaders: ['Authorization', 'X-Token', 'JWT', 'Bearer', 'X-Auth'],
        }],
        findings: Array.from({ length: 10 }, (_, index) => ({
          id: `finding-${index}`,
          finding: {
            category: 'API 信息',
            type: 'api-endpoint',
            value: `/api/${index}/${'y'.repeat(300)}`,
            severity: 'medium',
            confidence: 0.8,
            source: 'api',
            evidence: `fetch('/api/${index}/${'y'.repeat(1200)}')`,
          },
        })),
      });
    } finally {
      globalThis.fetch = originalFetch;
    }

    const logFile = join(process.cwd(), 'tmp-test-llm-logs', `${new Date().toISOString().slice(0, 10)}.log`);
    const logText = readFileSync(logFile, 'utf8');
    const promptLengthMatch = logText.match(/promptLength=(\d+)/);
    expect(promptLengthMatch).toBeTruthy();
    expect(Number(promptLengthMatch?.[1] ?? 0)).toBeLessThan(12000);
  });

  it('retries transient LLM provider network failures once', async () => {
    configureFileLogger({ fileEnabled: true, directory: 'tmp-test-llm-logs', level: 'info' });
    const originalFetch = globalThis.fetch;
    let callCount = 0;
    globalThis.fetch = async () => {
      callCount += 1;
      if (callCount === 1) {
        throw new TypeError('fetch failed', {
          cause: new Error('other side closed'),
        });
      }

      return new Response(
        JSON.stringify({
          choices: [{
            message: {
              content: JSON.stringify({
                secrets: [],
                findings: [{
                  id: 'finding-1',
                  is_risk: true,
                  category: 'API 信息',
                  type: 'api-endpoint',
                  severity: 'medium',
                  confidence: 0.9,
                  reason: 'confirmed after retry',
                }],
              }),
            },
          }],
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    };

    try {
      const provider = new DeepSeekProvider({
        apiKey: 'test-key',
        baseUrl: 'https://llm.example',
        model: 'deepseek-test',
        timeoutMs: 8000,
        logPrompts: false,
        logResponses: false,
        logRawPayloads: false,
      });

      const result = await provider.analyzeUnifiedBatch({
        apis: [],
        secrets: [],
        findings: [{
          id: 'finding-1',
          finding: {
            category: 'API 信息',
            type: 'api-endpoint',
            value: '/api/retry',
            severity: 'medium',
            confidence: 0.8,
            source: 'api',
            evidence: "fetch('/api/retry')",
          },
        }],
      });

      expect(result.findings[0]?.reason).toBe('confirmed after retry');
      expect(callCount).toBe(2);
    } finally {
      globalThis.fetch = originalFetch;
    }

    const logFile = join(process.cwd(), 'tmp-test-llm-logs', `${new Date().toISOString().slice(0, 10)}.log`);
    const logText = readFileSync(logFile, 'utf8');
    expect(logText).toContain('llm_provider_request_retry');
  });

  it('reviews all findings with LLM in full mode and drops rejected findings', async () => {
    const reviewedTypes: string[] = [];
    const provider: LLMProvider = {
      async analyzeSecret() {
        throw new Error('secret path should not be used');
      },
      async analyzeSecretsBatch() {
        return [];
      },
      async analyzeUnifiedBatch(input) {
        reviewedTypes.push(...input.findings.map((context) => context.finding.type));
        return {
          secrets: input.secrets.map((context) => ({
            id: context.candidate.id,
            is_secret: false,
            secret_type: context.candidate.type,
            severity: 'low' as const,
            confidence: 0.05,
            reason: 'false positive',
          })),
          findings: input.findings.map((context) => ({
            id: context.id,
            is_risk: context.finding.type === 'api-endpoint',
            category: context.finding.category,
            type: context.finding.type,
            severity: context.finding.severity,
            confidence: context.finding.type === 'api-endpoint' ? 0.91 : 0.05,
            reason: context.finding.type === 'api-endpoint' ? 'confirmed API exposure' : 'false positive',
          })),
        };
      },
    };

    const result = await analyzeJavaScript({
      content: `
        fetch('/api/confirmed');
        const adminPath = '/admin/panel';
      `,
      mode: 'full',
      llmAnalyzer: new LLMSecretAnalyzer(provider),
      unifiedLlmAnalyzer: new LLMUnifiedAnalyzer(provider),
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(reviewedTypes.length).toBeGreaterThan(1);
    expect(result.findings).toEqual([
      expect.objectContaining({
        type: 'api-endpoint',
        source: 'llm',
        confidence: 0.91,
        llmReview: expect.objectContaining({ confirmed: true, reason: 'confirmed API exposure' }),
      }),
    ]);
    expect(result.meta.analysis.llm.findingCandidateCount).toBe(reviewedTypes.length);
    expect(result.meta.analysis.llm.findingReviewedCount).toBe(reviewedTypes.length);
    expect(result.meta.analysis.llm.findingConfirmedCount).toBe(1);
    expect(result.meta.analysis.llm.findingRejectedCount).toBe(reviewedTypes.length - 1);
  });

  it('preserves rule findings when LLM finding review fails', async () => {
    let callCount = 0;
    const provider: LLMProvider = {
      async analyzeSecret() {
        throw new Error('secret path should not be used');
      },
      async analyzeSecretsBatch() {
        return [];
      },
      async analyzeUnifiedBatch() {
        callCount += 1;
        throw new Error('llm timeout');
      },
    };

    const result = await analyzeJavaScript({
      content: Array.from({ length: 18 }, (_, index) => `fetch('/api/preserved-${index}');`).join('\n'),
      mode: 'full',
      llmAnalyzer: new LLMSecretAnalyzer(provider),
      unifiedLlmAnalyzer: new LLMUnifiedAnalyzer(provider),
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(callCount).toBe(1);
    expect(result.findings).toEqual(expect.arrayContaining([expect.objectContaining({ type: 'api-endpoint', value: '/api/preserved-0' })]));
    expect(result.findings).toEqual(expect.arrayContaining([expect.objectContaining({ type: 'api-endpoint', value: '/api/preserved-17' })]));
    expect(result.findings.some((finding) => finding.llmReview?.reason.includes('preserved'))).toBe(true);
    expect(result.meta.analysis.llm.findingDroppedCount).toBe(result.meta.analysis.llm.findingCandidateCount);
  });

  it('allows configuring which findings enter LLM review', async () => {
    vi.spyOn(appConfig, 'getConfig').mockReturnValue({
      server: { host: '127.0.0.1', port: 0, logLevel: 'silent', bodyLimitMb: 20 },
      fetch: { timeoutMs: 10000, maxBytes: 10 * 1024 * 1024 },
      logging: { fileEnabled: false, directory: 'tmp', level: 'info' },
      auth: { enabled: false, headerName: 'x-api-key', apiKeys: [] },
      llm: {
        provider: 'deepseek',
        model: 'deepseek-v4-flash',
        apiKey: 'test',
        baseUrl: 'https://llm.example',
        timeoutMs: 8000,
        logPrompts: false,
        logResponses: false,
        logRawPayloads: false,
        reviewSecrets: false,
        reviewRiskCandidates: true,
        allowedSecretTypes: [],
        allowedRiskCategories: ['API 信息'],
      },
    });

    const reviewedCategories: string[] = [];
    const provider: LLMProvider = {
      async analyzeSecret() {
        throw new Error('secret path should not be used');
      },
      async analyzeSecretsBatch() {
        return [];
      },
      async analyzeUnifiedBatch(input) {
        reviewedCategories.push(...input.findings.map((context) => context.finding.category));
        return {
          secrets: [],
          findings: input.findings.map((context) => ({
            id: context.id,
            is_risk: true,
            category: context.finding.category,
            type: context.finding.type,
            severity: context.finding.severity,
            confidence: 0.9,
            reason: 'configured review',
          })),
        };
      },
    };

    const result = await analyzeJavaScript({
      content: `
        fetch('/api/configured');
        const adminPath = '/admin/panel';
      `,
      mode: 'full',
      llmAnalyzer: new LLMSecretAnalyzer(provider),
      unifiedLlmAnalyzer: new LLMUnifiedAnalyzer(provider),
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(reviewedCategories.length).toBeGreaterThan(0);
    expect(reviewedCategories.every((category) => category === 'API 信息')).toBe(true);
    expect(result.meta.analysis.llm.candidateCount).toBe(0);
    expect(result.meta.analysis.llm.findingCandidateCount).toBe(reviewedCategories.length);
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ category: 'API 信息', source: 'llm' }),
      expect.objectContaining({ category: '路由信息' }),
    ]));
  });

  it('allows configuring which secret types enter LLM review', async () => {
    vi.spyOn(appConfig, 'getConfig').mockReturnValue({
      server: { host: '127.0.0.1', port: 0, logLevel: 'silent', bodyLimitMb: 20 },
      fetch: { timeoutMs: 10000, maxBytes: 10 * 1024 * 1024 },
      logging: { fileEnabled: false, directory: 'tmp', level: 'info' },
      auth: { enabled: false, headerName: 'x-api-key', apiKeys: [] },
      llm: {
        provider: 'deepseek',
        model: 'deepseek-v4-flash',
        apiKey: 'test',
        baseUrl: 'https://llm.example',
        timeoutMs: 8000,
        logPrompts: false,
        logResponses: false,
        logRawPayloads: false,
        reviewSecrets: true,
        reviewRiskCandidates: false,
        allowedSecretTypes: ['bearer-token'],
        allowedRiskCategories: [],
      },
    });

    const reviewedSecretTypes: string[] = [];
    const provider: LLMProvider = {
      async analyzeSecret() {
        throw new Error('secret path should not be used');
      },
      async analyzeSecretsBatch() {
        return [];
      },
      async analyzeUnifiedBatch(input) {
        reviewedSecretTypes.push(...input.secrets.map((context) => context.candidate.type));
        return {
          secrets: input.secrets.map((context) => ({
            id: context.candidate.id,
            is_secret: true,
            secret_type: context.candidate.type,
            severity: 'high',
            confidence: 0.99,
            reason: 'configured secret review',
          })),
          findings: [],
        };
      },
    };

    const result = await analyzeJavaScript({
      content: `
        const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345';
        const password = 'admin123456';
      `,
      mode: 'full',
      llmAnalyzer: new LLMSecretAnalyzer(provider),
      unifiedLlmAnalyzer: new LLMUnifiedAnalyzer(provider),
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(reviewedSecretTypes).toEqual(['bearer-token']);
    expect(result.meta.analysis.llm.candidateCount).toBe(1);
    expect(result.secrets.some((secret) => secret.type === 'bearer-token' && secret.source === 'llm+regex')).toBe(true);
    expect(result.secrets.some((secret) => secret.source === 'regex')).toBe(true);
    expect(result.secrets).toEqual(expect.arrayContaining([
      expect.objectContaining({ type: 'bearer-token', source: 'llm+regex' }),
    ]));
  });
});
