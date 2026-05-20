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
});
