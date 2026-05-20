import * as t from '@babel/types';
import { calleeName } from '../propagation/stringResolver.js';
import { traverseAst } from '../traverser/traverseAst.js';

export interface WrapperRegistry {
  aliases: Map<string, string>;
  resolve(name: string): string;
  isHttpClient(name: string): boolean;
}

const knownClients = new Set(['axios', 'fetch', 'XMLHttpRequest']);

export function buildWrapperRegistry(ast: t.File): WrapperRegistry {
  const aliases = new Map<string, string>();

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
        const target = t.isBlockStatement(path.node.init.body)
          ? findReturnedHttpClient(path.node.init.body)
          : findCallTarget(path.node.init.body);
        if (target) {
          aliases.set(path.node.id.name, target);
        }
      }
    },
    FunctionDeclaration(path) {
      if (!path.node.id) {
        return;
      }

      const target = findReturnedHttpClient(path.node.body);
      if (target) {
        aliases.set(path.node.id.name, target);
      }
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

  return {
    aliases,
    resolve,
    isHttpClient: (name) => knownClients.has(resolve(name)) || aliases.has(name),
  };
}

function findReturnedHttpClient(body: t.BlockStatement): string | undefined {
  for (const statement of body.body) {
    if (t.isReturnStatement(statement) && statement.argument) {
      const target = findCallTarget(statement.argument);
      if (target) {
        return target;
      }
    }
  }
  return undefined;
}

function findCallTarget(node: t.Node): string | undefined {
  if (t.isCallExpression(node)) {
    const name = calleeName(node.callee);
    if (name === 'axios' || name.startsWith('axios.') || name === 'fetch') {
      return name.split('.')[0];
    }
  }
  if (t.isIdentifier(node) && knownClients.has(node.name)) {
    return node.name;
  }
  return undefined;
}
