import { describe, expect, it, vi } from 'vitest';
import { LLMSecretAnalyzer } from '../llm/analyzers/llmSecretAnalyzer.js';
import { AsyncTaskQueue } from '../llm/analyzers/secretQueue.js';
import type { LLMProvider, SecretContext } from '../types/llm.js';

describe('llm queue', () => {
  it('rate limits queued LLM jobs to 60 per minute', async () => {
    vi.useFakeTimers();
    const startedAt: number[] = [];
    const provider: LLMProvider = {
      async analyzeSecret() {
        startedAt.push(Date.now());
        return {
          is_secret: true,
          secret_type: 'token',
          severity: 'high',
          confidence: 0.9,
          reason: 'test',
        };
      },
    };
    const analyzer = new LLMSecretAnalyzer(provider, undefined, new AsyncTaskQueue(1, 1000));
    const context = (value: string): SecretContext => ({
      candidate: {
        id: value,
        type: 'token',
        value,
        severity: 'high',
        evidence: value,
      },
      context: value,
      nearbyApis: [],
      nearbyHeaders: [],
    });

    analyzer.enqueue(context('a'));
    analyzer.enqueue(context('b'));
    analyzer.enqueue(context('c'));

    await vi.advanceTimersByTimeAsync(0);
    expect(startedAt).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(999);
    expect(startedAt).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(startedAt).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1000);
    expect(startedAt).toHaveLength(3);
    expect(startedAt[1] - startedAt[0]).toBeGreaterThanOrEqual(1000);
    expect(startedAt[2] - startedAt[1]).toBeGreaterThanOrEqual(1000);

    vi.useRealTimers();
  });
});
