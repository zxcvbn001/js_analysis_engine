import * as t from '@babel/types';
import type { ApiResult, ParamResult } from '../../types/results.js';
import { calleeName, createStringResolver, memberName } from '../../engine/propagation/stringResolver.js';
import type { MethodForwarder, WrapperRegistry } from '../../engine/wrapper/wrapperRegistry.js';
import {
  extractHeaders,
  extractJsonLikeStringParams,
  extractObjectParams,
  extractParamsFromConfig,
  extractPathParams,
  extractQueryParams,
  extractValueParam,
  resolveUrlParams,
} from '../params/paramExtractor.js';
import { extractAuthSignals } from '../auth/authExtractor.js';
import { uniqueBy } from '../../utils/dedupe.js';
import { traverseAst } from '../../engine/traverser/traverseAst.js';

export interface ApiExtraction {
  apis: ApiResult[];
  params: ParamResult[];
  auth: string[];
}

const httpMethods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options']);

export function extractApis(ast: t.File, constants: Map<string, string>, wrappers: WrapperRegistry): ApiExtraction {
  const resolver = createStringResolver(constants);
  const apis: ApiResult[] = [];
  const params: ParamResult[] = [];
  const xhrHeaders = new Map<string, string[]>();
  const xhrOpenApis = new Map<string, ApiResult>();
  const auth = new Set<string>();
  const xhrInstances = collectXhrInstances(ast);

  traverseAst(ast, {
    CallExpression(path) {
      const api = recoverCall(path.node, resolver, wrappers, xhrInstances);
      if (!api) {
        return;
      }

      if (api.xhrHeaderFor) {
        const values = xhrHeaders.get(api.xhrHeaderFor) ?? [];
        values.push(...(api.result.headers ?? []));
        xhrHeaders.set(api.xhrHeaderFor, values);
        const existingApi = xhrOpenApis.get(api.xhrHeaderFor);
        if (existingApi) {
          existingApi.headers = uniqueBy([...(existingApi.headers ?? []), ...(api.result.headers ?? [])], (header) => header);
          existingApi.auth = existingApi.auth ?? api.result.auth;
        }
        params.push(...api.params);
        for (const signal of api.auth) {
          auth.add(signal);
        }
        return;
      }

      if (api.xhrInstance) {
        const headers = xhrHeaders.get(api.xhrInstance) ?? [];
        api.result.headers = uniqueBy([...(api.result.headers ?? []), ...headers], (header) => header);
      }

      apis.push(api.result);
      if (api.xhrInstance) {
        xhrOpenApis.set(api.xhrInstance, api.result);
      }
      params.push(...api.params);
      for (const signal of api.auth) {
        auth.add(signal);
      }
    },
  });

  return {
    apis: uniqueBy(apis, (api) => `${api.method ?? ''}:${api.url}:${api.source ?? ''}`),
    params: uniqueBy(params, (param) => `${param.location}:${param.api ?? ''}:${param.name}`),
    auth: [...auth],
  };
}

interface RecoveredCall {
  result: ApiResult;
  params: ParamResult[];
  auth: string[];
  xhrInstance?: string;
  xhrHeaderFor?: string;
}

function recoverCall(
  node: t.CallExpression,
  resolver: ReturnType<typeof createStringResolver>,
  wrappers: WrapperRegistry,
  xhrInstances: Set<string>,
): RecoveredCall | undefined {
  if (t.isIdentifier(node.callee) && node.callee.name === 'fetch') {
    return recoverFetch(node, resolver);
  }

  if (t.isIdentifier(node.callee)) {
    const forwarder = wrappers.getForwarder(node.callee.name);
    if (forwarder?.kind === 'config') {
      const recovered = recoverRequestConfigCall(node, resolver, node.callee.name);
      if (recovered) {
        return recovered;
      }
    }
    if (forwarder?.kind === 'method') {
      const recovered = recoverForwardedMethodCall(node, resolver, forwarder, node.callee.name);
      if (recovered) {
        return recovered;
      }
    }
  }

  if (t.isCallExpression(node.callee)) {
    const recovered = recoverRequestConfigCall(node, resolver, `${calleeName(node.callee.callee)}()`);
    if (recovered) {
      return recovered;
    }
  }

    if (t.isMemberExpression(node.callee)) {
      const source = memberName(node.callee);
      const methodName = methodFromMember(node.callee);
      const objectName = objectFromMember(node.callee);
      const resolvedObject = objectName ? wrappers.resolve(objectName) : undefined;

      if (isJQueryObject(objectName) && methodName === 'ajax') {
        return recoverJQueryAjax(node, resolver, source);
      }

      if (isJQueryObject(objectName) && methodName && ['get', 'post'].includes(methodName)) {
        return recoverMethodCall(node, resolver, methodName.toUpperCase(), source);
      }

      if ((resolvedObject === 'axios' || objectName === 'axios' || wrappers.isHttpClient(objectName ?? '')) && methodName && httpMethods.has(methodName)) {
        return recoverMethodCall(node, resolver, methodName.toUpperCase(), source);
      }

    if (methodName === 'request' && (resolvedObject === 'axios' || wrappers.isHttpClient(objectName ?? ''))) {
      return recoverRequestConfigCall(node, resolver, source);
    }

      if (methodName === 'open' && source.endsWith('.open') && objectName && xhrInstances.has(objectName)) {
        return recoverXhrOpen(node, resolver, source, objectName);
      }

      if (methodName === 'setrequestheader' && source.toLowerCase().endsWith('.setrequestheader') && objectName && xhrInstances.has(objectName)) {
        return recoverXhrHeader(node, resolver, source, objectName);
      }
    }

  if (t.isIdentifier(node.callee) && wrappers.resolve(node.callee.name) === 'axios') {
    return recoverRequestConfigCall(node, resolver, node.callee.name);
  }

  return undefined;
}

function recoverJQueryAjax(
  node: t.CallExpression,
  resolver: ReturnType<typeof createStringResolver>,
  source: string,
): RecoveredCall | undefined {
  const firstArg = node.arguments[0];
  if (!firstArg || !t.isExpression(firstArg)) {
    return undefined;
  }

  if (!t.isObjectExpression(firstArg)) {
    const url = resolver.resolve(firstArg).value;
    if (!url || !isLikelyRequestUrl(url)) {
      return undefined;
    }
    const params = [...extractPathParams(url, url), ...extractQueryParams(url, url), ...resolveUrlParams(firstArg, resolver, url)];
    return {
      result: { url, method: 'GET', params: params.map((param) => param.name), source },
      params,
      auth: extractAuthSignals([], [url]),
    };
  }

  let url: string | undefined;
  let method: string | undefined;
  let dataNode: t.Node | undefined;

  for (const property of firstArg.properties) {
    if (!t.isObjectProperty(property)) {
      continue;
    }

    const key = t.isIdentifier(property.key) ? property.key.name : t.isStringLiteral(property.key) ? property.key.value : undefined;
    if (key === 'url') {
      url = resolver.resolve(property.value).value;
    }
    if (key && ['method', 'type'].includes(key.toLowerCase())) {
      method = resolver.resolve(property.value).value?.toUpperCase();
    }
    if (key === 'data') {
      dataNode = property.value;
    }
  }

  if (!url || !isLikelyRequestUrl(url)) {
    return undefined;
  }

  const headers = extractHeaders(firstArg, url);
  const params = [
    ...extractPathParams(url, url),
    ...extractQueryParams(url, url),
    ...extractParamsFromConfig(firstArg, url),
    ...extractObjectParams(dataNode, method === 'GET' ? 'query' : 'body', url),
  ];
  const auth = extractAuthSignals(headers, [url, ...headers]);

  return {
    result: { url, method: method ?? 'GET', params: params.map((param) => param.name), headers, auth: auth[0], source },
    params,
    auth,
  };
}

function recoverXhrHeader(
  node: t.CallExpression,
  resolver: ReturnType<typeof createStringResolver>,
  source: string,
  xhrInstance: string,
): RecoveredCall | undefined {
  const headerNode = node.arguments[0];
  if (!headerNode || !t.isExpression(headerNode)) {
    return undefined;
  }

  const header = resolver.resolve(headerNode).value;
  if (!header) {
    return undefined;
  }

  const auth = extractAuthSignals([header], [header]);
  return {
    result: { url: 'XMLHttpRequest', headers: [header], auth: auth[0], source },
    params: [{ name: header, location: 'header', source }],
    auth,
    xhrHeaderFor: xhrInstance,
  };
}

function recoverFetch(node: t.CallExpression, resolver: ReturnType<typeof createStringResolver>): RecoveredCall | undefined {
  const urlNode = node.arguments[0];
  if (!urlNode || !t.isExpression(urlNode)) {
    return undefined;
  }

  const url = resolver.resolve(urlNode).value;
  if (!url || !isLikelyRequestUrl(url)) {
    return undefined;
  }

  const config = node.arguments[1];
  const method = t.isObjectExpression(config) ? methodFromConfig(config) : undefined;
  const headers = t.isObjectExpression(config) ? extractHeaders(config, url) : [];
  const params = [
    ...extractPathParams(url, url),
    ...extractQueryParams(url, url),
    ...resolveUrlParams(urlNode, resolver, url),
    ...(t.isObjectExpression(config) ? extractParamsFromConfig(config, url) : []),
  ];
  const auth = extractAuthSignals(headers, [url, ...headers]);

  return {
    result: { url, method: method ?? 'GET', params: params.map((param) => param.name), headers, auth: auth[0], source: 'fetch' },
    params,
    auth,
  };
}

function recoverMethodCall(
  node: t.CallExpression,
  resolver: ReturnType<typeof createStringResolver>,
  method: string,
  source: string,
): RecoveredCall | undefined {
  const urlNode = node.arguments[0];
  if (!urlNode || !t.isExpression(urlNode)) {
    return undefined;
  }

  const url = resolver.resolve(urlNode).value;
  if (!url || !isLikelyRequestUrl(url)) {
    return undefined;
  }

  const bodyOrConfig = node.arguments[1];
  const config = node.arguments[2];
  const inlineConfig = method === 'GET' || method === 'HEAD' ? bodyOrConfig : config;
  const bodyParams = t.isObjectExpression(bodyOrConfig) && method !== 'GET' && method !== 'HEAD' ? extractObjectParams(bodyOrConfig, 'body', url) : [];
  const bodyStringParams = method !== 'GET' && method !== 'HEAD' ? extractJsonLikeStringParams(bodyOrConfig, 'body', url) : [];
  const bodyValueParams = method !== 'GET' && method !== 'HEAD' ? extractValueParam(bodyOrConfig, 'body', url) : [];
  const configParams = t.isObjectExpression(inlineConfig) ? extractParamsFromConfig(inlineConfig, url) : [];
  const headers = t.isObjectExpression(inlineConfig) ? extractHeaders(inlineConfig, url) : [];
  const params = [
    ...extractPathParams(url, url),
    ...extractQueryParams(url, url),
    ...resolveUrlParams(urlNode, resolver, url),
    ...bodyParams,
    ...bodyStringParams,
    ...bodyValueParams,
    ...configParams,
  ];
  const auth = extractAuthSignals(headers, [url, ...headers]);

  return {
    result: { url, method, params: params.map((param) => param.name), headers, auth: auth[0], source },
    params,
    auth,
  };
}

function recoverForwardedMethodCall(
  node: t.CallExpression,
  resolver: ReturnType<typeof createStringResolver>,
  forwarder: MethodForwarder,
  source: string,
): RecoveredCall | undefined {
  const urlNode = node.arguments[forwarder.urlArgIndex];
  if (!urlNode || !t.isExpression(urlNode)) {
    return undefined;
  }

  const url = resolver.resolve(urlNode).value;
  if (!url || !isLikelyRequestUrl(url)) {
    return undefined;
  }

  const bodyNode = forwarder.bodyArgIndex === undefined ? undefined : node.arguments[forwarder.bodyArgIndex];
  const queryNode = forwarder.queryArgIndex === undefined ? undefined : node.arguments[forwarder.queryArgIndex];
  const configNode = forwarder.configArgIndex === undefined ? undefined : node.arguments[forwarder.configArgIndex];
  const headers = t.isObjectExpression(configNode) ? extractHeaders(configNode, url) : [];
  const params = [
    ...extractPathParams(url, url),
    ...extractQueryParams(url, url),
    ...resolveUrlParams(urlNode, resolver, url),
    ...(t.isObjectExpression(bodyNode) ? extractObjectParams(bodyNode, 'body', url) : []),
    ...extractJsonLikeStringParams(bodyNode, 'body', url),
    ...extractValueParam(bodyNode, 'body', url),
    ...(t.isObjectExpression(queryNode) ? extractObjectParams(queryNode, 'query', url) : []),
    ...(t.isObjectExpression(configNode) ? extractParamsFromConfig(configNode, url) : []),
  ];
  const auth = extractAuthSignals(headers, [url, ...headers]);

  return {
    result: {
      url,
      method: forwarder.method,
      params: params.map((param) => param.name),
      headers,
      auth: auth[0],
      source,
    },
    params,
    auth,
  };
}

function recoverRequestConfigCall(
  node: t.CallExpression,
  resolver: ReturnType<typeof createStringResolver>,
  source: string,
): RecoveredCall | undefined {
  const config = node.arguments[0];
  if (!config || !t.isObjectExpression(config)) {
    return undefined;
  }

  let url: string | undefined;
  let method: string | undefined;
  for (const property of config.properties) {
    if (!t.isObjectProperty(property)) {
      continue;
    }
    const key = t.isIdentifier(property.key) ? property.key.name : t.isStringLiteral(property.key) ? property.key.value : undefined;
    if (key === 'url') {
      url = resolver.resolve(property.value).value;
    }
    if (key === 'method') {
      method = resolver.resolve(property.value).value?.toUpperCase();
    }
  }

  if (!url || !isLikelyRequestUrl(url)) {
    return undefined;
  }

  const headers = extractHeaders(config, url);
  const params = [...extractPathParams(url, url), ...extractQueryParams(url, url), ...extractParamsFromConfig(config, url)];
  const auth = extractAuthSignals(headers, [url, ...headers]);

  return {
    result: { url, method, params: params.map((param) => param.name), headers, auth: auth[0], source },
    params,
    auth,
  };
}

function recoverXhrOpen(node: t.CallExpression, resolver: ReturnType<typeof createStringResolver>, source: string, xhrInstance: string): RecoveredCall | undefined {
  const methodNode = node.arguments[0];
  const urlNode = node.arguments[1];
  if (!methodNode || !urlNode || !t.isExpression(methodNode) || !t.isExpression(urlNode)) {
    return undefined;
  }

  const method = resolver.resolve(methodNode).value?.toUpperCase();
  const url = resolver.resolve(urlNode).value;
  if (!url || !isLikelyRequestUrl(url)) {
    return undefined;
  }

  const params = [...extractPathParams(url, url), ...extractQueryParams(url, url), ...resolveUrlParams(urlNode, resolver, url)];
  return {
    result: { url, method, params: params.map((param) => param.name), source },
    params,
    auth: extractAuthSignals([], [url]),
    xhrInstance,
  };
}

function methodFromMember(node: t.MemberExpression): string | undefined {
  if (t.isIdentifier(node.property)) {
    return node.property.name.toLowerCase();
  }
  if (t.isStringLiteral(node.property)) {
    return node.property.value.toLowerCase();
  }
  return undefined;
}

function objectFromMember(node: t.MemberExpression): string | undefined {
  const object = node.object;
  if (t.isIdentifier(object)) {
    return object.name;
  }
  if (t.isMemberExpression(object)) {
    return memberName(object);
  }
  return undefined;
}

function isJQueryObject(name: string | undefined): boolean {
  return name === '$' || name === 'jQuery';
}

function collectXhrInstances(ast: t.File): Set<string> {
  const instances = new Set<string>();

  traverseAst(ast, {
    VariableDeclarator(path) {
      if (t.isIdentifier(path.node.id) && isXhrNewExpression(path.node.init)) {
        instances.add(path.node.id.name);
      }
    },
    AssignmentExpression(path) {
      if (t.isIdentifier(path.node.left) && isXhrNewExpression(path.node.right)) {
        instances.add(path.node.left.name);
      }
    },
  });

  return instances;
}

function isXhrNewExpression(node: t.Node | null | undefined): boolean {
  return Boolean(node && t.isNewExpression(node) && t.isIdentifier(node.callee) && node.callee.name === 'XMLHttpRequest');
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
  if (/^https?:\/\//i.test(trimmed) || /^\/\//.test(trimmed)) {
    return true;
  }
  if (trimmed.startsWith('/')) {
    return true;
  }
  if (trimmed.includes('${')) {
    return trimmed.startsWith('/') || /^https?:/i.test(trimmed);
  }
  return false;
}

function methodFromConfig(config: t.ObjectExpression): string | undefined {
  for (const property of config.properties) {
    if (!t.isObjectProperty(property)) {
      continue;
    }
    const key = t.isIdentifier(property.key) ? property.key.name : t.isStringLiteral(property.key) ? property.key.value : undefined;
    if (key?.toLowerCase() === 'method') {
      const value = t.isStringLiteral(property.value) ? property.value.value : undefined;
      return value?.toUpperCase();
    }
  }
  return undefined;
}
