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
  return parse(extractScriptContent(content), {
    sourceType: 'unambiguous',
    allowAwaitOutsideFunction: true,
    allowImportExportEverywhere: true,
    errorRecovery: true,
    plugins,
  });
}

export function extractScriptContent(content: string): string {
  if (!content.includes('<script')) {
    return content;
  }

  const scripts: string[] = [];
  const scriptPattern = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  for (const match of content.matchAll(scriptPattern)) {
    if (match[1]?.trim()) {
      scripts.push(match[1]);
    }
  }

  return scripts.length > 0 ? scripts.join('\n') : content;
}
