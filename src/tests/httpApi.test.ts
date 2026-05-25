import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildServer } from '../api/server.js';
import type { AppConfig } from '../config/appConfig.js';

describe('http api', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(join(process.cwd(), 'tmp-test-logs'), { recursive: true, force: true });
  });

  it('returns Burp-friendly analysis JSON', async () => {
    const app = await buildServer();
    const response = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        url: 'https://example.com/app.js',
        content: "fetch('/api/user')",
        fast_mode: true,
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.success).toBe(true);
    expect(body.apis[0].url).toBe('/api/user');
    expect(body.assets).toEqual([]);
    expect(body.groups.endpoints.apis[0].url).toBe('/api/user');
    await app.close();
  });

  it('returns a compact response when response_mode=compact', async () => {
    const app = await buildServer();
    const response = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        url: 'https://example.com/app.js',
        content: "fetch('/api/user')",
        fast_mode: true,
        response_mode: 'compact',
      },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.success).toBe(true);
    expect(body.summary.apiCount).toBe(1);
    expect(body.apis[0].url).toBe('/api/user');
    expect(body.groups).toBeUndefined();
    expect(body.meta).toBeUndefined();
    expect(body.risk).toBeUndefined();
    await app.close();
  });

  it('validates bad requests', async () => {
    const app = await buildServer();
    const response = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {},
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().success).toBe(false);
    await app.close();
  });

  it('accepts url-only analysis by downloading content', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response("fetch('/downloaded.js-api')", {
        status: 200,
        headers: {
          'content-type': 'application/javascript',
        },
      }),
    );

    const app = await buildServer(testConfig());
    const response = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        url: 'https://example.com/app.js',
        fast_mode: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().apis[0].url).toBe('/downloaded.js-api');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      'https://example.com/app.js',
      expect.objectContaining({ method: 'GET' }),
    );

    await app.close();
  });

  it('prefers content over url when both are provided', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    const app = await buildServer(testConfig());
    const response = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        url: 'https://example.com/app.js',
        content: "fetch('/from-content')",
        fast_mode: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().apis[0].url).toBe('/from-content');
    expect(fetchMock).not.toHaveBeenCalled();

    await app.close();
  });

  it('writes input and result summaries to file logs', async () => {
    const app = await buildServer(testConfig({ logDir: 'tmp-test-logs' }));
    const response = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        url: 'https://example.com/app.js',
        content: `
          const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345';
          fetch('/api/log-summary', { method: 'POST' });
        `,
        fast_mode: true,
      },
    });

    expect(response.statusCode).toBe(200);
    const logFile = join(process.cwd(), 'tmp-test-logs', `${new Date().toISOString().slice(0, 10)}.log`);
    const logText = readFileSync(logFile, 'utf8');
    expect(logText).toContain('analyze_js_request_received');
    expect(logText).toContain('analyze_js_content_prepared');
    expect(logText).toContain('analyze_js_success');
    expect(logText).toContain('contentLength');
    expect(logText).toContain('sha256');
    expect(logText).toContain('apiCount');
    expect(logText).toContain('findingCategoryCounts');
    expect(logText).toContain('endpointGroupCount');
    expect(logText).toContain('exposureGroupCount');
    expect(logText).toContain('scriptGroupCount');
    expect(logText).toContain('llmCandidateCount');

    await app.close();
  });

  it('uses full analysis mode by default unless fast mode is explicit', async () => {
    const app = await buildServer(testConfig());
    const defaultResponse = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        content: "const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345'",
      },
    });

    expect(defaultResponse.statusCode).toBe(200);
    expect(defaultResponse.json().success).toBe(true);

    const fastResponse = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        content: "const token = 'Bearer abcdefghijklmnopqrstuvwxyz12345'",
        fast_mode: true,
      },
    });

    expect(fastResponse.statusCode).toBe(200);
    expect(fastResponse.json().success).toBe(true);

    await app.close();
  });

  it('submits async analysis tasks and returns results by id', async () => {
    const app = await buildServer(testConfig());
    const submitted = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        content: "fetch('/async-api')",
        async: true,
      },
    });

    expect(submitted.statusCode).toBe(202);
    const taskId = submitted.json().task_id;
    expect(taskId).toBeTruthy();

    let taskBody: { task?: { status: string; result?: { success: boolean; apis?: Array<{ url: string }> } } } = {};
    for (let index = 0; index < 10; index += 1) {
      const taskResponse = await app.inject({
        method: 'GET',
        url: `/analyze/tasks/${taskId}`,
      });
      taskBody = taskResponse.json();
      if (taskBody.task?.status === 'completed') {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }

    expect(taskBody.task?.status).toBe('completed');
    expect(taskBody.task?.result?.success).toBe(true);
    expect(taskBody.task?.result?.apis?.[0]?.url).toBe('/async-api');

    await app.close();
  });

  it('returns compact task results when async request uses response_mode=compact', async () => {
    const app = await buildServer(testConfig());
    const submitted = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        content: "fetch('/async-compact-api')",
        async: true,
        response_mode: 'compact',
      },
    });

    expect(submitted.statusCode).toBe(202);
    const taskId = submitted.json().task_id;
    expect(taskId).toBeTruthy();

    let taskBody: { task?: { status: string; result?: { success: boolean; summary?: { apiCount: number }; apis?: Array<{ url: string }>; groups?: unknown } } } = {};
    for (let index = 0; index < 10; index += 1) {
      const taskResponse = await app.inject({
        method: 'GET',
        url: `/analyze/tasks/${taskId}`,
      });
      taskBody = taskResponse.json();
      if (taskBody.task?.status === 'completed') {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }

    expect(taskBody.task?.status).toBe('completed');
    expect(taskBody.task?.result?.success).toBe(true);
    expect(taskBody.task?.result?.summary?.apiCount).toBe(1);
    expect(taskBody.task?.result?.apis?.[0]?.url).toBe('/async-compact-api');
    expect(taskBody.task?.result?.groups).toBeUndefined();

    await app.close();
  });

  it('returns a clear error and writes logs when url download fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('fetch failed'));

    const app = await buildServer(testConfig({ logDir: 'tmp-test-logs' }));
    const response = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        url: 'https://bad.example/app.js',
      },
    });

    expect(response.statusCode).toBe(502);
    expect(response.json().error.message).toContain('Failed to download JS from https://bad.example/app.js');

    const logFile = join(process.cwd(), 'tmp-test-logs', `${new Date().toISOString().slice(0, 10)}.log`);
    expect(existsSync(logFile)).toBe(true);
    expect(readFileSync(logFile, 'utf8')).toContain('download_js_failed');

    await app.close();
  });

  it('returns fallback results and parse diagnostics when downloaded content is not parseable JavaScript', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<!doctype html><html><body>requestConfig: { url: "/fallback/api", method: "post" }</body></html>', {
        status: 200,
        headers: {
          'content-type': 'text/html',
        },
      }),
    );

    const app = await buildServer(testConfig({ logDir: 'tmp-test-logs' }));
    const response = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        url: 'http://example.com/assets/global/scripts/app.min.js',
        fast_mode: true,
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().success).toBe(true);
    expect(response.json().apis).toEqual(expect.arrayContaining([expect.objectContaining({ url: '/fallback/api' })]));

    const logFile = join(process.cwd(), 'tmp-test-logs', `${new Date().toISOString().slice(0, 10)}.log`);
    const logText = readFileSync(logFile, 'utf8');
    expect(logText).toContain('analyze_js_parse_failed');
    expect(logText).toContain('analyze_js_text_fallback_completed');
    expect(logText).toContain('looksLikeHtml');

    await app.close();
  });

  it('requires an API key when auth is enabled', async () => {
    const app = await buildServer(testConfig({ authEnabled: true }));

    const denied = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      payload: {
        content: "fetch('/api/user')",
      },
    });
    expect(denied.statusCode).toBe(401);

    const allowed = await app.inject({
      method: 'POST',
      url: '/analyze/js',
      headers: {
        'x-api-key': 'test-key',
      },
      payload: {
        content: "fetch('/api/user')",
      },
    });
    expect(allowed.statusCode).toBe(200);
    expect(allowed.json().success).toBe(true);

    const health = await app.inject({
      method: 'GET',
      url: '/health',
    });
    expect(health.statusCode).toBe(200);

    await app.close();
  });
});

function testConfig(options?: { authEnabled?: boolean; logDir?: string }): AppConfig {
  return {
    server: {
      host: '127.0.0.1',
      port: 0,
      logLevel: 'silent',
      bodyLimitMb: 20,
    },
    fetch: {
      timeoutMs: 10000,
      maxBytes: 10 * 1024 * 1024,
    },
    logging: {
      fileEnabled: true,
      directory: options?.logDir ?? 'tmp-test-logs',
      level: 'info',
    },
    auth: {
      enabled: options?.authEnabled ?? false,
      headerName: 'x-api-key',
      apiKeys: ['test-key'],
    },
    llm: {
      provider: 'none',
      model: 'deepseek-v4-flash',
      apiKey: '',
      baseUrl: 'https://api.deepseek.com',
      timeoutMs: 8000,
      logPrompts: true,
      logResponses: true,
      logRawPayloads: false,
    },
  };
}
