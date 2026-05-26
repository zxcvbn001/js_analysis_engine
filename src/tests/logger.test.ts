import { afterEach, describe, expect, it } from 'vitest';
import { configureFileLogger, configureLlmConsoleLogger, createPinoConsoleStream, logInfo } from '../utils/logger.js';

describe('logger formatting', () => {
  afterEach(() => {
    configureFileLogger({ fileEnabled: false, directory: 'logs', level: 'info' });
    configureLlmConsoleLogger();
  });

  it('formats pino json logs into readable text lines', () => {
    let output = '';
    const stream = createPinoConsoleStream({
      write(chunk: string | Uint8Array): boolean {
        output += String(chunk);
        return true;
      },
    } as NodeJS.WritableStream);

    stream.write(JSON.stringify({
      level: 50,
      time: 1779751260364,
      pid: 1,
      hostname: 'host',
      reqId: 'req-1',
      req: {
        method: 'POST',
        url: '/analyze/js',
        host: 'localhost:3000',
      },
      msg: 'incoming request',
    }));

    expect(output).toContain('[ERROR]');
    expect(output).toContain('incoming request');
    expect(output).toContain('method="POST"');
    expect(output).toContain('url="/analyze/js"');
    expect(output).not.toContain('"level":50');
  });

  it('mirrors LLM logs to console even when file logging is disabled', () => {
    let output = '';
    configureFileLogger({ fileEnabled: false, directory: 'logs', level: 'info' });
    configureLlmConsoleLogger({
      enabled: true,
      stdout: {
        write(message: string): void {
          output += message;
        },
      },
      stderr: {
        write(message: string): void {
          output += message;
        },
      },
    });

    logInfo('analyze_js_start', { url: 'https://example.com/app.js' });
    logInfo('llm_provider_prompt_built', { operation: 'unified-batch', promptLength: 123 });

    expect(output).toContain('[INFO]');
    expect(output).toContain('llm_provider_prompt_built');
    expect(output).toContain('operation="unified-batch"');
    expect(output).toContain('promptLength=123');
    expect(output).not.toContain('analyze_js_start');
  });
});
