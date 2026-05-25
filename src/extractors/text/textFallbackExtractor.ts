import type { ApiExtraction } from '../api/apiExtractor.js';
import type { BaseUrlCandidate } from '../api/baseUrlExtractor.js';
import { extractAuthSignals } from '../auth/authExtractor.js';
import { extractPathParams, extractQueryParams } from '../params/paramExtractor.js';
import type { ApiResult, AssetResult, ParamResult } from '../../types/results.js';
import { uniqueBy } from '../../utils/dedupe.js';

const MAX_TEXT_APIS = 500;
const MAX_TEXT_ASSETS = 500;
const MAX_WINDOW_CHARS = 1200;

export function extractTextApis(content: string): ApiExtraction {
  const apis: ApiResult[] = [];
  const params: ParamResult[] = [];
  const auth = new Set<string>();

  const addApi = (input: { url: string; method?: string; source: string; index: number }): void => {
    if (apis.length >= MAX_TEXT_APIS || !isLikelyRequestUrl(input.url)) {
      return;
    }

    const windowText = textWindow(content, input.index);
    const headers = extractHeadersFromText(windowText);
    const method = (input.method ?? methodFromText(windowText) ?? 'GET').toUpperCase();
    const apiParams = [
      ...extractPathParams(input.url, input.url),
      ...extractQueryParams(input.url, input.url),
      ...extractBodyParamsFromText(windowText, method === 'GET' ? 'query' : 'body', input.url),
      ...headers.map((name) => ({ name, location: 'header' as const, api: input.url, source: 'text-header' })),
    ];
    const apiAuth = extractAuthSignals(headers, [input.url, windowText]);
    for (const signal of apiAuth) {
      auth.add(signal);
    }

    const classified = classifyRecoveredApi({
      url: input.url,
      method,
      params: uniqueBy(apiParams, (param) => `${param.location}:${param.name}`).map((param) => param.name),
      headers,
      auth: apiAuth[0],
      source: input.source,
    });
    if (classified.kind !== 'api') {
      return;
    }

    apis.push(classified);
    params.push(...apiParams);
  };

  scan(content, /\bfetch\s*\(\s*(["'`])([^"'`\r\n]{1,2048})\1/g, (match) => {
    addApi({ url: match[2] ?? '', source: 'text:fetch', index: match.index });
  });

  scan(content, /\b(?:axios|[A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|head|options)\s*\(\s*(["'`])([^"'`\r\n]{1,2048})\2/gi, (match) => {
    addApi({ url: match[3] ?? '', method: match[1], source: 'text:method-call', index: match.index });
  });

  scan(content, /\b(?:\$|jQuery)\.(get|post)\s*\(\s*(["'`])([^"'`\r\n]{1,2048})\2/gi, (match) => {
    addApi({ url: match[3] ?? '', method: match[1], source: 'text:jquery-method', index: match.index });
  });

  scan(content, /\.open\s*\(\s*(["'`])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*(["'`])([^"'`\r\n]{1,2048})\3/gi, (match) => {
    addApi({ url: match[4] ?? '', method: match[2], source: 'text:xhr-open', index: match.index });
  });

  scan(content, /\burl\s*:\s*(["'`])([^"'`\r\n]{1,2048})\1/g, (match) => {
    addApi({ url: match[2] ?? '', source: 'text:config-url', index: match.index });
  });

  return {
    apis: uniqueBy(apis, (api) => `${api.method ?? ''}:${api.url}:${api.source ?? ''}`),
    params: uniqueBy(params, (param) => `${param.location}:${param.api ?? ''}:${param.name}`),
    auth: [...auth],
  };
}

export function extractTextAssets(content: string): AssetResult[] {
  const assets: AssetResult[] = [];
  const addAsset = (url: string, source: string): void => {
    if (assets.length >= MAX_TEXT_ASSETS || !looksLikeAssetUrl(url)) {
      return;
    }
    assets.push({
      url,
      type: assetTypeFromUrl(url),
      source,
    });
  };

  scan(content, /<script\b[^>]*\bsrc\s*=\s*(["'])([^"']{1,2048})\1/gi, (match) => {
    addAsset(match[2] ?? '', 'text:script-src');
  });

  scan(content, /(["'`])([^"'`\s]{1,2048}\.(?:js|mjs|css|map)(?:\?[^"'`\s]*)?)\1/gi, (match) => {
    addAsset(match[2] ?? '', 'text:quoted-asset');
  });

  return uniqueBy(assets, (asset) => `${asset.type}:${asset.url}:${asset.source ?? ''}`);
}

export function extractTextBaseUrlCandidates(content: string): BaseUrlCandidate[] {
  const candidates: BaseUrlCandidate[] = [];
  scan(content, /\b(baseUrl|baseURL|apiBase|apiHost|gateway|domainName)\s*:\s*(["'`])([^"'`\r\n]{1,2048})\2/g, (match) => {
    const value = normalizeBaseUrl(match[3] ?? '');
    if (looksLikeBaseUrl(value)) {
      candidates.push({ value, source: `text:${match[1]}` });
    }
  });

  return uniqueBy(candidates, (candidate) => candidate.value);
}

function scan(content: string, pattern: RegExp, callback: (match: RegExpExecArray) => void): void {
  pattern.lastIndex = 0;
  while (true) {
    const match = pattern.exec(content);
    if (!match) {
      return;
    }
    callback(match);
    if (match[0].length === 0) {
      pattern.lastIndex += 1;
    }
  }
}

function textWindow(content: string, index: number): string {
  const start = Math.max(0, index - Math.floor(MAX_WINDOW_CHARS / 3));
  const end = Math.min(content.length, index + MAX_WINDOW_CHARS);
  return content.slice(start, end);
}

function methodFromText(value: string): string | undefined {
  const match = /\b(?:method|type)\s*:\s*(["'`])?([A-Za-z]+)\1?/i.exec(value);
  return match?.[2];
}

function extractHeadersFromText(value: string): string[] {
  const headers = new Set<string>();
  const block = /\bheaders\s*:\s*\{([\s\S]{0,700}?)\}/i.exec(value)?.[1];
  if (!block) {
    return [];
  }
  for (const match of block.matchAll(/["']?([A-Za-z][\w-]{1,80})["']?\s*:/g)) {
    if (match[1]) {
      headers.add(match[1]);
    }
  }
  return [...headers];
}

function extractBodyParamsFromText(value: string, location: ParamResult['location'], api?: string): ParamResult[] {
  const params = new Set<string>();
  for (const block of bodyBlocks(value)) {
    for (const match of block.matchAll(/["']([A-Za-z_$][\w$.-]{0,100})["']\s*:/g)) {
      if (match[1]) {
        params.add(match[1]);
      }
    }
    for (const match of block.matchAll(/\b([A-Za-z_$][\w$.-]{0,100})\s*:/g)) {
      if (match[1] && !['url', 'method', 'type', 'headers', 'data', 'body', 'params'].includes(match[1])) {
        params.add(match[1]);
      }
    }
  }
  return [...params].map((name) => ({ name, location, api, source: 'text-body' }));
}

function bodyBlocks(value: string): string[] {
  const blocks: string[] = [];
  for (const match of value.matchAll(/\b(?:data|body|params|query)\s*:\s*([\s\S]{0,900})/gi)) {
    if (match[1]) {
      blocks.push(match[1]);
    }
  }
  return blocks;
}

function isLikelyRequestUrl(url: string): boolean {
  const trimmed = url.trim();
  if (!trimmed || trimmed.length > 2048) {
    return false;
  }
  if (/^(?:XMLHttpRequest|_blank|_self|_parent|_top|true|false|null|undefined|\d+)$/.test(trimmed)) {
    return false;
  }
  if (/^(?:javascript|data|mailto|tel):/i.test(trimmed)) {
    return false;
  }
  return /^https?:\/\//i.test(trimmed) || /^\/\//.test(trimmed) || trimmed.startsWith('/');
}

function classifyRecoveredApi(api: ApiResult): ApiResult {
  const candidate = api.resolvedUrl ?? api.url;
  const kind = classifyUrl(candidate);
  return {
    ...api,
    kind,
    confidence: api.confidence ?? confidenceForKind(kind, candidate),
  };
}

function classifyUrl(url: string): ApiResult['kind'] {
  const normalized = url.split('?')[0]?.toLowerCase() ?? '';

  if (
    normalized === '/favicon.ico'
    || normalized === '/manifest.json'
    || normalized.startsWith('/static/')
    || normalized.startsWith('/assets/')
    || normalized.startsWith('/images/')
    || normalized.startsWith('/img/')
    || normalized.startsWith('/fonts/')
    || /\.(?:png|jpe?g|gif|svg|ico|webp|bmp|css|woff2?|ttf|eot|otf)(?:$|\?)/i.test(normalized)
  ) {
    return 'asset';
  }

  if (/\.(?:m?js)(?:$|\?)/i.test(normalized) && /(?:^|\/)(?:static|assets|js|scripts)\//i.test(normalized)) {
    return 'asset';
  }

  return 'api';
}

function confidenceForKind(kind: ApiResult['kind'], url: string): 'low' | 'medium' | 'high' {
  if (kind === 'asset') {
    return 'low';
  }
  if (url.startsWith('/')) {
    return 'medium';
  }
  return 'low';
}

function looksLikeAssetUrl(url: string): boolean {
  return /\.(?:js|mjs|css|map)(?:$|\?)/i.test(url.trim());
}

function assetTypeFromUrl(url: string): AssetResult['type'] {
  const normalized = url.split('?')[0]?.toLowerCase() ?? '';
  if (normalized.endsWith('.js') || normalized.endsWith('.mjs')) {
    return 'script';
  }
  if (normalized.endsWith('.css')) {
    return 'style';
  }
  return 'asset';
}

function looksLikeBaseUrl(value: string): boolean {
  return /^https?:\/\//i.test(value) || /^\/\//.test(value) || value.startsWith('/');
}

function normalizeBaseUrl(value: string): string {
  return value.trim().replace(/\/+$/, '');
}
