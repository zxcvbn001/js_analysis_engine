import { parse, type ParserPlugin } from '@babel/parser';
import type { File } from '@babel/types';

const plugins: ParserPlugin[] = [
  'jsx',
  'typescript',
  'classProperties',
  'classPrivateProperties',
  'classPrivateMethods',
  'decorators-legacy',
  'dynamicImport',
  'importMeta',
  'objectRestSpread',
  'optionalChaining',
  'nullishCoalescingOperator',
  'topLevelAwait',
];

export function parseJavaScript(content: string): File {
  return parseScript(extractScriptContent(stripBom(content)));
}

export interface JavaScriptContentDiagnostics {
  rawLength: number;
  scriptContentLength: number;
  scriptBlockCount: number;
  scriptExtractionUsed: boolean;
  startsWithBom: boolean;
  leadingWhitespaceLength: number;
  firstNonWhitespaceCodePoint?: number;
  firstNonWhitespaceKind: 'empty' | 'html' | 'json' | 'string' | 'identifier' | 'operator' | 'control' | 'other';
  looksLikeHtml: boolean;
  looksLikeJson: boolean;
  nulByteCount: number;
  replacementCharCount: number;
}

export interface JavaScriptParseResult {
  ast: File;
  ok: boolean;
  fallbackUsed: boolean;
  errorCount: number;
  diagnostics: JavaScriptContentDiagnostics;
  error?: unknown;
}

export function parseJavaScriptWithDiagnostics(content: string): JavaScriptParseResult {
  const normalized = stripBom(content);
  const scripts = extractScriptBlocks(normalized);
  const scriptContent = scripts.length > 0 ? scripts.join('\n') : normalized;
  const diagnostics = diagnoseJavaScriptContent(content, scriptContent, scripts.length);

  try {
    const ast = parseScript(scriptContent);
    const parserErrors = parserErrorsOf(ast);
    return {
      ast,
      ok: true,
      fallbackUsed: false,
      errorCount: parserErrors.length,
      diagnostics,
    };
  } catch (error) {
    return {
      ast: createEmptyJavaScriptAst(),
      ok: false,
      fallbackUsed: true,
      errorCount: 1,
      diagnostics,
      error,
    };
  }
}

export function createEmptyJavaScriptAst(): File {
  return parseScript('');
}

export function extractScriptContent(content: string): string {
  const normalized = stripBom(content);
  const scripts = extractScriptBlocks(normalized);
  return scripts.length > 0 ? scripts.join('\n') : normalized;
}

function parseScript(content: string): File {
  return parse(content, {
    sourceType: 'unambiguous',
    allowAwaitOutsideFunction: true,
    allowImportExportEverywhere: true,
    errorRecovery: true,
    plugins,
  });
}

function extractScriptBlocks(content: string): string[] {
  if (!content.includes('<script')) {
    return [];
  }

  const scripts: string[] = [];
  const scriptPattern = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  for (const match of content.matchAll(scriptPattern)) {
    if (match[1]?.trim()) {
      scripts.push(match[1]);
    }
  }

  return scripts;
}

function diagnoseJavaScriptContent(rawContent: string, scriptContent: string, scriptBlockCount: number): JavaScriptContentDiagnostics {
  const leadingWhitespace = scriptContent.match(/^\s*/)?.[0].length ?? 0;
  const first = scriptContent.slice(leadingWhitespace, leadingWhitespace + 1);
  const trimmedStart = scriptContent.slice(leadingWhitespace, leadingWhitespace + 64).toLowerCase();

  return {
    rawLength: rawContent.length,
    scriptContentLength: scriptContent.length,
    scriptBlockCount,
    scriptExtractionUsed: scriptBlockCount > 0,
    startsWithBom: rawContent.charCodeAt(0) === 0xfeff,
    leadingWhitespaceLength: leadingWhitespace,
    firstNonWhitespaceCodePoint: first ? first.codePointAt(0) : undefined,
    firstNonWhitespaceKind: classifyFirstChar(first),
    looksLikeHtml: /^<!doctype\b|^<html\b|^<head\b|^<body\b|^</i.test(trimmedStart),
    looksLikeJson: /^[{[]/.test(trimmedStart),
    nulByteCount: countMatches(rawContent, '\u0000'),
    replacementCharCount: countMatches(rawContent, '\ufffd'),
  };
}

function classifyFirstChar(value: string): JavaScriptContentDiagnostics['firstNonWhitespaceKind'] {
  if (!value) {
    return 'empty';
  }
  if (value === '<') {
    return 'html';
  }
  if (value === '{' || value === '[') {
    return 'json';
  }
  if (value === '"' || value === '\'' || value === '`') {
    return 'string';
  }
  if (/[$_A-Za-z]/.test(value)) {
    return 'identifier';
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    return 'control';
  }
  if (/[()[\]{}.,;:+\-*/%=&|!?<>~^]/.test(value)) {
    return 'operator';
  }
  return 'other';
}

function countMatches(value: string, needle: string): number {
  if (!needle) {
    return 0;
  }
  let count = 0;
  let offset = 0;
  while (true) {
    const index = value.indexOf(needle, offset);
    if (index === -1) {
      return count;
    }
    count += 1;
    offset = index + needle.length;
  }
}

function parserErrorsOf(ast: File): unknown[] {
  return ((ast as File & { errors?: unknown[] }).errors ?? []);
}

function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}
