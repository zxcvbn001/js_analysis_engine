import { errorFields, logError, logInfo, logWarn } from './logger.js';

export interface FetchContentOptions {
  timeoutMs: number;
  maxBytes: number;
}

export async function fetchTextContent(url: string, options: FetchContentOptions): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs);
  const startedAt = Date.now();

  try {
    logInfo('download_js_start', {
      url,
      timeoutMs: options.timeoutMs,
      maxBytes: options.maxBytes,
    });

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        Accept: 'application/javascript,text/javascript,text/plain,*/*',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to download JS from ${url}: HTTP ${response.status}`);
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength && Number(contentLength) > options.maxBytes) {
      throw new Error(`Downloaded JS from ${url} exceeds maxBytes (${options.maxBytes})`);
    }

    if (!response.body) {
      const text = await response.text();
      logInfo('download_js_success', {
        url,
        bytes: Buffer.byteLength(text, 'utf8'),
        durationMs: Date.now() - startedAt,
      });
      return text;
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      totalBytes += value.byteLength;
      if (totalBytes > options.maxBytes) {
        await reader.cancel();
        throw new Error(`Downloaded JS from ${url} exceeds maxBytes (${options.maxBytes})`);
      }
      chunks.push(value);
    }

    const merged = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }

    const text = new TextDecoder('utf-8', { fatal: false }).decode(merged);
    logInfo('download_js_success', {
      url,
      bytes: totalBytes,
      durationMs: Date.now() - startedAt,
    });
    return text;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      logWarn('download_js_timeout', {
        url,
        timeoutMs: options.timeoutMs,
        durationMs: Date.now() - startedAt,
        ...errorFields(error),
      });
      throw new Error(`Timed out downloading JS from ${url} after ${options.timeoutMs}ms`);
    }
    logError('download_js_failed', {
      url,
      durationMs: Date.now() - startedAt,
      ...errorFields(error),
    });
    if (error instanceof TypeError && error.message === 'fetch failed') {
      throw new Error(`Failed to download JS from ${url}: fetch failed. Check network, DNS, TLS certificate, proxy, or target availability.`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
