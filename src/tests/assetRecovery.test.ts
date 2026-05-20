import { describe, expect, it } from 'vitest';
import { analyzeJavaScript } from '../engine/analyzers/javascriptAnalyzer.js';

describe('asset recovery', () => {
  it('recovers webpack chunk asset urls from runtime filename maps', async () => {
    const result = await analyzeJavaScript({
      content: `
        function a(e){
          return s.p + "assets/js/" + ({}[e] || e) + "." + {
            "chunk-01d475cb": "4ef8f8dc",
            "chunk-06304042": "34ac8d05"
          }[e] + ".js"
        }
      `,
    });

    expect(result.success).toBe(true);
    if (!result.success) {
      return;
    }

    expect(result.apis).toHaveLength(0);
    expect(result.assets).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          url: 'assets/js/chunk-01d475cb.4ef8f8dc.js',
          type: 'script',
          chunkName: 'chunk-01d475cb',
        }),
        expect.objectContaining({
          url: 'assets/js/chunk-06304042.34ac8d05.js',
          type: 'script',
          chunkName: 'chunk-06304042',
        }),
      ]),
    );
  });
});
