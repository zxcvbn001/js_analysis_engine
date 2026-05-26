import { describe, expect, it } from 'vitest';
import { createPinoConsoleStream } from '../utils/logger.js';

describe('logger formatting', () => {
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
});
