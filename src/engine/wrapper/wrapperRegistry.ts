import * as t from '@babel/types';
import { calleeName } from '../propagation/stringResolver.js';
import { traverseAst } from '../traverser/traverseAst.js';

export interface ConfigForwarder {
  kind: 'config';
  target: string;
}

export interface MethodForwarder {
  kind: 'method';
  method: string;
  target: string;
  urlArgIndex: number;
  bodyArgIndex?: number;
  queryArgIndex?: number;
  configArgIndex?: number;
}

export type RequestForwarder = ConfigForwarder | MethodForwarder;

export interface WrapperRegistry {
  aliases: Map<string, string>;
  forwarders: Map<string, RequestForwarder>;
  resolve(name: string): string;
  isHttpClient(name: string): boolean;
  getForwarder(name: string): RequestForwarder | undefined;
}

const knownClients = new Set(['axios', 'fetch', 'XMLHttpRequest']);
const httpMethods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options']);

export function buildWrapperRegistry(ast: t.File): WrapperRegistry {
  const aliases = new Map<string, string>();
  const forwarders = new Map<string, RequestForwarder>();
  const functions = new Map<string, { params: t.Identifier[]; body: t.BlockStatement | t.Expression }>();

  traverseAst(ast, {
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id) || !path.node.init) {
        return;
      }

      if (t.isIdentifier(path.node.init) && knownClients.has(path.node.init.name)) {
        aliases.set(path.node.id.name, path.node.init.name);
      }

      if (t.isCallExpression(path.node.init) && t.isMemberExpression(path.node.init.callee)) {
        const callee = calleeName(path.node.init.callee);
        if (callee === 'axios.create') {
          aliases.set(path.node.id.name, 'axios');
        }
      }

      if (t.isArrowFunctionExpression(path.node.init) || t.isFunctionExpression(path.node.init)) {
        functions.set(path.node.id.name, {
          params: identifierParams(path.node.init.params),
          body: path.node.init.body,
        });
      }
    },
    FunctionDeclaration(path) {
      if (!path.node.id) {
        return;
      }

      functions.set(path.node.id.name, {
        params: identifierParams(path.node.params),
        body: path.node.body,
      });
    },
  });

  const resolve = (name: string): string => {
    let current = name;
    const seen = new Set<string>();
    while (aliases.has(current) && !seen.has(current)) {
      seen.add(current);
      current = aliases.get(current) ?? current;
    }
    return current;
  };

  let changed = true;
  let rounds = 0;
  while (changed && rounds < 8) {
    changed = false;
    rounds += 1;

    for (const [name, fn] of functions) {
      const aliasTarget = findReturnedHttpClient(fn.body, resolve, aliases);
      if (aliasTarget && aliases.get(name) !== aliasTarget) {
        aliases.set(name, aliasTarget);
        changed = true;
      }

      const forwarder = summarizeForwarder(fn.body, fn.params, resolve, aliases);
      if (forwarder && JSON.stringify(forwarders.get(name)) !== JSON.stringify(forwarder)) {
        forwarders.set(name, forwarder);
        changed = true;
      }
    }
  }

  return {
    aliases,
    forwarders,
    resolve,
    isHttpClient: (name) => knownClients.has(resolve(name)) || aliases.has(name),
    getForwarder: (name) => forwarders.get(name),
  };
}

function identifierParams(params: Array<t.Identifier | t.Pattern | t.RestElement>): t.Identifier[] {
  return params.filter((param): param is t.Identifier => t.isIdentifier(param));
}

function findReturnedHttpClient(
  body: t.BlockStatement | t.Expression,
  resolve: (name: string) => string,
  aliases: Map<string, string>,
): string | undefined {
  if (t.isExpression(body)) {
    return findCallTarget(body, resolve, aliases);
  }

  for (const statement of body.body) {
    if (t.isReturnStatement(statement) && statement.argument) {
      const target = findCallTarget(statement.argument, resolve, aliases);
      if (target) {
        return target;
      }
    }
  }
  return undefined;
}

function findCallTarget(node: t.Node, resolve: (name: string) => string, aliases: Map<string, string>): string | undefined {
  if (t.isCallExpression(node)) {
    const name = calleeName(node.callee);
    if (name === 'axios' || name.startsWith('axios.') || name === 'fetch') {
      return name.split('.')[0];
    }
    if (t.isIdentifier(node.callee) && isKnownHttpClient(node.callee.name, resolve, aliases)) {
      return resolve(node.callee.name);
    }
    if (t.isMemberExpression(node.callee)) {
      const object = objectName(node.callee);
      if (object && isKnownHttpClient(object, resolve, aliases)) {
        return resolve(object);
      }
    }
  }
  if (t.isIdentifier(node) && isKnownHttpClient(node.name, resolve, aliases)) {
    return resolve(node.name);
  }
  return undefined;
}

function summarizeForwarder(
  body: t.BlockStatement | t.Expression,
  params: t.Identifier[],
  resolve: (name: string) => string,
  aliases: Map<string, string>,
): RequestForwarder | undefined {
  const returned = returnedExpression(body);
  if (!returned || !t.isCallExpression(returned)) {
    return undefined;
  }

  const direct = summarizeDirectConfigForwarder(returned, params, resolve, aliases);
  if (direct) {
    return direct;
  }

  return summarizeMethodForwarder(returned, params, resolve, aliases);
}

function returnedExpression(body: t.BlockStatement | t.Expression): t.Expression | undefined {
  if (t.isExpression(body)) {
    return body;
  }

  for (const statement of body.body) {
    if (t.isReturnStatement(statement) && statement.argument && t.isExpression(statement.argument)) {
      return statement.argument;
    }
  }
  return undefined;
}

function summarizeDirectConfigForwarder(
  node: t.CallExpression,
  params: t.Identifier[],
  resolve: (name: string) => string,
  aliases: Map<string, string>,
): ConfigForwarder | undefined {
  const firstArg = node.arguments[0];
  if (!firstArg || !t.isIdentifier(firstArg) || !params.some((param) => param.name === firstArg.name)) {
    return undefined;
  }

  if (t.isIdentifier(node.callee) && isKnownHttpClient(node.callee.name, resolve, aliases)) {
    return { kind: 'config', target: resolve(node.callee.name) };
  }

  if (t.isMemberExpression(node.callee) && methodFromMember(node.callee) === 'request') {
    const object = objectName(node.callee);
    if (object && isKnownHttpClient(object, resolve, aliases)) {
      return { kind: 'config', target: resolve(object) };
    }
  }

  return undefined;
}

function summarizeMethodForwarder(
  node: t.CallExpression,
  params: t.Identifier[],
  resolve: (name: string) => string,
  aliases: Map<string, string>,
): MethodForwarder | undefined {
  if (!t.isMemberExpression(node.callee)) {
    return undefined;
  }

  const method = methodFromMember(node.callee);
  const object = objectName(node.callee);
  if (!method || !httpMethods.has(method) || !object || !isKnownHttpClient(object, resolve, aliases)) {
    return undefined;
  }

  const urlArgIndex = paramIndex(node.arguments[0], params);
  if (urlArgIndex === undefined) {
    return undefined;
  }

  const summary: MethodForwarder = {
    kind: 'method',
    method: method.toUpperCase(),
    target: resolve(object),
    urlArgIndex,
  };

  const bodyArgIndex = paramIndex(node.arguments[1], params);
  if (bodyArgIndex !== undefined && !['GET', 'HEAD'].includes(summary.method)) {
    summary.bodyArgIndex = bodyArgIndex;
  } else if (bodyArgIndex !== undefined) {
    summary.configArgIndex = bodyArgIndex;
  }

  const configArgIndex = paramIndex(node.arguments[2], params);
  if (configArgIndex !== undefined) {
    summary.configArgIndex = configArgIndex;
  }

  const inlineConfig = t.isObjectExpression(node.arguments[1]) ? node.arguments[1] : t.isObjectExpression(node.arguments[2]) ? node.arguments[2] : undefined;
  if (inlineConfig) {
    for (const property of inlineConfig.properties) {
      if (!t.isObjectProperty(property)) {
        continue;
      }
      const key = t.isIdentifier(property.key) ? property.key.name.toLowerCase() : t.isStringLiteral(property.key) ? property.key.value.toLowerCase() : undefined;
      const index = paramIndex(property.value, params);
      if (index === undefined) {
        continue;
      }
      if (key === 'params' || key === 'query') {
        summary.queryArgIndex = index;
      }
      if (key === 'data' || key === 'body') {
        summary.bodyArgIndex = index;
      }
      if (key === 'headers') {
        summary.configArgIndex = index;
      }
    }
  }

  return summary;
}

function paramIndex(node: t.Node | null | undefined, params: t.Identifier[]): number | undefined {
  if (!node || !t.isIdentifier(node)) {
    return undefined;
  }
  const index = params.findIndex((param) => param.name === node.name);
  return index >= 0 ? index : undefined;
}

function isKnownHttpClient(name: string, resolve: (name: string) => string, aliases: Map<string, string>): boolean {
  return knownClients.has(resolve(name)) || aliases.has(name);
}

function objectName(node: t.MemberExpression): string | undefined {
  if (t.isIdentifier(node.object)) {
    return node.object.name;
  }
  return undefined;
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
