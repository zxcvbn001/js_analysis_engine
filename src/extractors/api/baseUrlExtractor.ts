import * as t from '@babel/types';
import { traverseAst } from '../../engine/traverser/traverseAst.js';

export interface BaseUrlCandidate {
  value: string;
  source: string;
}

export function extractBaseUrlCandidates(ast: t.File, scriptUrl?: string): BaseUrlCandidate[] {
  const candidates: BaseUrlCandidate[] = [];
  const host = safeHost(scriptUrl);
  const protocol = safeProtocol(scriptUrl) ?? 'https:';
  const runtimeConstants = collectRuntimeConstants(ast, { protocol });

  traverseAst(ast, {
    ObjectProperty(path) {
      const key = propertyKey(path.node.key);
      if (!key || !['baseUrl', 'baseURL', 'domainName'].includes(key)) {
        return;
      }

      if (!t.isExpression(path.node.value)) {
        return;
      }

      for (const value of resolveBaseUrlExpression(path.node.value, { host, protocol, runtimeConstants })) {
        candidates.push({
          value,
          source: `object.${key}`,
        });
      }
    },
  });

  return dedupeBaseUrls(candidates);
}

export function enrichApisWithBaseUrl<T extends { url: string; resolvedUrl?: string; baseUrl?: string; confidence?: 'low' | 'medium' | 'high'; notes?: string[] }>(
  apis: T[],
  candidates: BaseUrlCandidate[],
): T[] {
  const preferred = candidates[0]?.value;
  if (!preferred) {
    return apis.map((api) => ({
      ...api,
      confidence: api.confidence ?? confidenceForUrl(api.url),
      notes: needsRuntimeBaseUrl(api.url) ? [...(api.notes ?? []), 'relative-url-without-static-base-url'] : api.notes,
    }));
  }

  return apis.map((api) => {
    if (!api.url.startsWith('/') || isAbsoluteOrProtocolRelativeUrl(api.url)) {
      return {
        ...api,
        confidence: api.confidence ?? confidenceForUrl(api.url),
      };
    }

    return {
      ...api,
      baseUrl: preferred,
      resolvedUrl: joinUrl(preferred, api.url),
      confidence: 'high',
      notes: [...(api.notes ?? []), 'resolved-from-static-base-url'],
    };
  });
}

function resolveBaseUrlExpression(node: t.Node, context: { host?: string; protocol: string; runtimeConstants: Map<string, string> }): string[] {
  if (t.isStringLiteral(node)) {
    return node.value ? [node.value] : [];
  }

  if (t.isIdentifier(node)) {
    const value = context.runtimeConstants.get(node.name);
    return value ? [value] : [];
  }

  if (t.isMemberExpression(node) && isLocationProtocol(node)) {
    return [context.protocol];
  }

  if (t.isBinaryExpression(node) && node.operator === '+') {
    const leftValues = resolveBaseUrlExpression(node.left, context);
    const rightValues = resolveBaseUrlExpression(node.right, context);
    const values: string[] = [];
    for (const left of leftValues.length ? leftValues : ['']) {
      for (const right of rightValues.length ? rightValues : ['']) {
        const value = `${left}${right}`;
        if (looksLikeBaseUrl(value)) {
          values.push(normalizeBaseUrl(value));
        }
      }
    }
    return values;
  }

  if (t.isConditionalExpression(node)) {
    const selected = selectConditionalBranch(node, context.host);
    if (selected) {
      return resolveBaseUrlExpression(selected, context);
    }
    return [
      ...resolveBaseUrlExpression(node.consequent, context),
      ...resolveBaseUrlExpression(node.alternate, context),
    ];
  }

  return [];
}

function selectConditionalBranch(node: t.ConditionalExpression, host?: string): t.Node | undefined {
  if (!host || !t.isBinaryExpression(node.test) || !['===', '=='].includes(node.test.operator)) {
    return undefined;
  }

  const left = staticString(node.test.left);
  const right = staticString(node.test.right);
  if (left === host) {
    return node.consequent;
  }
  if (right === host) {
    return node.consequent;
  }
  if (left !== undefined || right !== undefined) {
    return node.alternate;
  }
  return undefined;
}

function staticString(node: t.Node): string | undefined {
  if (t.isStringLiteral(node)) {
    return node.value;
  }
  return undefined;
}

function collectRuntimeConstants(ast: t.File, context: { protocol: string }): Map<string, string> {
  const constants = new Map<string, string>();
  let changed = true;
  let rounds = 0;

  while (changed && rounds < 3) {
    changed = false;
    rounds += 1;

    traverseAst(ast, {
      VariableDeclarator(path) {
        if (!t.isIdentifier(path.node.id) || !path.node.init || !t.isExpression(path.node.init)) {
          return;
        }

        const value = resolveRuntimeConstant(path.node.init, constants, context);
        if (value !== undefined && constants.get(path.node.id.name) !== value) {
          constants.set(path.node.id.name, value);
          changed = true;
        }
      },
      AssignmentExpression(path) {
        if (!t.isIdentifier(path.node.left) || !t.isExpression(path.node.right)) {
          return;
        }

        const value = resolveRuntimeConstant(path.node.right, constants, context);
        if (value !== undefined && constants.get(path.node.left.name) !== value) {
          constants.set(path.node.left.name, value);
          changed = true;
        }
      },
    });
  }

  return constants;
}

function resolveRuntimeConstant(node: t.Expression, constants: Map<string, string>, context: { protocol: string }): string | undefined {
  if (t.isStringLiteral(node)) {
    return node.value;
  }
  if (t.isIdentifier(node)) {
    return constants.get(node.name);
  }
  if (t.isMemberExpression(node) && isLocationProtocol(node)) {
    return context.protocol;
  }
  if (t.isBinaryExpression(node) && node.operator === '+') {
    const left = t.isExpression(node.left) ? resolveRuntimeConstant(node.left, constants, context) : undefined;
    const right = resolveRuntimeConstant(node.right, constants, context);
    if (left !== undefined && right !== undefined) {
      return `${left}${right}`;
    }
  }
  return undefined;
}

function propertyKey(node: t.Node): string | undefined {
  if (t.isIdentifier(node)) {
    return node.name;
  }
  if (t.isStringLiteral(node) || t.isNumericLiteral(node)) {
    return String(node.value);
  }
  return undefined;
}

function memberName(node: t.MemberExpression): string {
  const objectName = t.isMemberExpression(node.object)
    ? memberName(node.object)
    : t.isIdentifier(node.object)
      ? node.object.name
      : 'unknown';
  const propertyName = t.isIdentifier(node.property)
    ? node.property.name
    : t.isStringLiteral(node.property)
      ? node.property.value
      : 'unknown';
  return `${objectName}.${propertyName}`;
}

function isLocationProtocol(node: t.MemberExpression): boolean {
  const name = memberName(node);
  return name === 'document.location.protocol' || name === 'window.location.protocol' || name === 'location.protocol';
}

function safeHost(url?: string): string | undefined {
  try {
    return url ? new URL(url).host : undefined;
  } catch {
    return undefined;
  }
}

function safeProtocol(url?: string): string | undefined {
  try {
    return url ? new URL(url).protocol : undefined;
  } catch {
    return undefined;
  }
}

function looksLikeBaseUrl(value: string): boolean {
  return /^https?:\/\//i.test(value) || /^\/\//.test(value) || value.startsWith('/');
}

function normalizeBaseUrl(value: string): string {
  return value.replace(/\/+$/, '');
}

function dedupeBaseUrls(candidates: BaseUrlCandidate[]): BaseUrlCandidate[] {
  const seen = new Set<string>();
  return candidates.filter((candidate) => {
    const key = candidate.value;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function joinUrl(baseUrl: string, path: string): string {
  if (isAbsoluteOrProtocolRelativeUrl(path)) {
    return path;
  }
  if (baseUrl.endsWith('/') && path.startsWith('/')) {
    return `${baseUrl}${path.slice(1)}`;
  }
  if (!baseUrl.endsWith('/') && !path.startsWith('/')) {
    return `${baseUrl}/${path}`;
  }
  return `${baseUrl}${path}`;
}

function confidenceForUrl(url: string): 'low' | 'medium' | 'high' {
  if (isAbsoluteOrProtocolRelativeUrl(url)) {
    return 'high';
  }
  if (url.startsWith('/')) {
    return 'medium';
  }
  return 'low';
}

function needsRuntimeBaseUrl(url: string): boolean {
  return url.startsWith('/') && !isAbsoluteOrProtocolRelativeUrl(url);
}

function isAbsoluteOrProtocolRelativeUrl(url: string): boolean {
  return /^https?:\/\//i.test(url) || /^\/\//.test(url);
}
