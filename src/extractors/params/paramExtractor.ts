import * as t from '@babel/types';
import type { ParamResult } from '../../types/results.js';
import type { StringResolver } from '../../engine/propagation/stringResolver.js';

export function extractPathParams(url: string, api?: string): ParamResult[] {
  const params: ParamResult[] = [];
  const patterns = [/\$\{([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\}/g, /:([A-Za-z_$][\w$]*)/g];

  for (const pattern of patterns) {
    for (const match of url.matchAll(pattern)) {
      if (match[1]) {
        params.push({ name: match[1], location: 'path', api, source: 'url' });
      }
    }
  }

  return params;
}

export function extractQueryParams(url: string, api?: string): ParamResult[] {
  const query = url.split('?')[1];
  if (!query) {
    return [];
  }

  return query
    .split('&')
    .map((part) => part.split('=')[0])
    .filter(Boolean)
    .map((name) => ({ name, location: 'query' as const, api, source: 'url' }));
}

export function extractObjectParams(node: t.Node | null | undefined, location: ParamResult['location'], api?: string): ParamResult[] {
  if (!node || !t.isObjectExpression(node)) {
    return [];
  }

  const params: ParamResult[] = [];
  for (const property of node.properties) {
    if (!t.isObjectProperty(property)) {
      continue;
    }

    const name = propertyKeyName(property.key);
    if (name) {
      params.push({ name, location, api, source: 'object' });
    }
  }

  return params;
}

export function extractJsonLikeStringParams(node: t.Node | null | undefined, location: ParamResult['location'], api?: string): ParamResult[] {
  const fragments = collectStringFragments(node);
  if (fragments.length === 0) {
    return [];
  }

  const text = fragments.join('');
  const params = new Set<string>();
  const keyPattern = /["']([A-Za-z_$][\w$.-]*)["']\s*:/g;
  for (const match of text.matchAll(keyPattern)) {
    if (match[1]) {
      params.add(match[1]);
    }
  }

  return [...params].map((name) => ({ name, location, api, source: 'json-string' }));
}

export function extractHeaders(node: t.Node | null | undefined, api?: string): string[] {
  if (!node || !t.isObjectExpression(node)) {
    return [];
  }

  const headersProperty = node.properties.find((property) => {
    if (!t.isObjectProperty(property)) {
      return false;
    }
    const name = propertyKeyName(property.key);
    return name?.toLowerCase() === 'headers';
  });

  if (!headersProperty || !t.isObjectProperty(headersProperty) || !t.isObjectExpression(headersProperty.value)) {
    return [];
  }

  return extractObjectParams(headersProperty.value, 'header', api).map((param) => param.name);
}

export function extractParamsFromConfig(node: t.Node | null | undefined, api?: string): ParamResult[] {
  if (!node || !t.isObjectExpression(node)) {
    return [];
  }

  const params: ParamResult[] = [];
  for (const property of node.properties) {
    if (!t.isObjectProperty(property)) {
      continue;
    }
    const name = propertyKeyName(property.key);
    if (!name) {
      continue;
    }

    if (['params', 'query'].includes(name.toLowerCase())) {
      params.push(...extractObjectParams(property.value, 'query', api));
    }
    if (['data', 'body'].includes(name.toLowerCase())) {
      params.push(...extractObjectParams(property.value, 'body', api));
      params.push(...extractJsonLikeStringParams(property.value, 'body', api));
    }
    if (name.toLowerCase() === 'headers') {
      params.push(...extractObjectParams(property.value, 'header', api));
    }
  }

  return params;
}

function collectStringFragments(node: t.Node | null | undefined): string[] {
  if (!node) {
    return [];
  }

  if (t.isStringLiteral(node)) {
    return [node.value];
  }

  if (t.isTemplateLiteral(node)) {
    return node.quasis.map((quasi) => quasi.value.cooked ?? quasi.value.raw);
  }

  if (t.isBinaryExpression(node) && node.operator === '+') {
    return [...collectStringFragments(node.left), ...collectStringFragments(node.right)];
  }

  if (t.isCallExpression(node) && t.isMemberExpression(node.callee)) {
    const property = node.callee.property;
    if (t.isIdentifier(property) && ['stringify', 'parseForm', 'formSerialize'].includes(property.name)) {
      return node.arguments.flatMap((argument) => (t.isNode(argument) ? collectStringFragments(argument) : []));
    }
  }

  return [];
}

export function resolveUrlParams(node: t.Node, resolver: StringResolver, api?: string): ParamResult[] {
  const resolved = resolver.resolve(node);
  return resolved.params.map((name) => ({ name, location: 'path' as const, api, source: 'expression' }));
}

export function propertyKeyName(node: t.Node): string | undefined {
  if (t.isIdentifier(node)) {
    return node.name;
  }
  if (t.isStringLiteral(node) || t.isNumericLiteral(node)) {
    return String(node.value);
  }
  return undefined;
}
