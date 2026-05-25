import * as t from '@babel/types';
import type { FunctionRegistry } from '../callgraph/functionRegistry.js';
import { traverseAst } from '../traverser/traverseAst.js';

export interface StringResolution {
  value?: string;
  params: string[];
}

export interface StringResolver {
  resolve(node: t.Node | null | undefined): StringResolution;
  inlineCall(node: t.CallExpression): t.Expression | undefined;
  constants: Map<string, string>;
}

const MAX_STRING_LENGTH = 4096;

export function createStringResolver(constants: Map<string, string>, functionRegistry?: FunctionRegistry): StringResolver {
  const resolve = (node: t.Node | null | undefined, depth = 0): StringResolution => {
    if (!node || depth > 20) {
      return { params: [] };
    }

    if (t.isStringLiteral(node)) {
      return { value: node.value, params: [] };
    }

    if (t.isNumericLiteral(node) || t.isBooleanLiteral(node)) {
      return { value: String(node.value), params: [] };
    }

    if (t.isIdentifier(node)) {
      const value = constants.get(node.name);
      return value === undefined ? { params: [node.name] } : { value, params: [] };
    }

    if (t.isTemplateLiteral(node)) {
      let value = '';
      const params: string[] = [];

      for (let index = 0; index < node.quasis.length; index += 1) {
        value += node.quasis[index]?.value.cooked ?? node.quasis[index]?.value.raw ?? '';
        const expression = node.expressions[index];
        if (expression) {
          const resolved = resolve(expression, depth + 1);
          params.push(...resolved.params);
          value += resolved.value ?? placeholderFor(expression);
        }
      }

      return { value: trimLong(value), params };
    }

    if (t.isBinaryExpression(node) && node.operator === '+') {
      const left = resolve(node.left, depth + 1);
      const right = resolve(node.right, depth + 1);
      if (left.value !== undefined || right.value !== undefined) {
        return {
          value: trimLong((left.value ?? placeholderFor(node.left)) + (right.value ?? placeholderFor(node.right))),
          params: [...left.params, ...right.params],
        };
      }
    }

    if (t.isLogicalExpression(node) && ['||', '??'].includes(node.operator)) {
      const right = resolve(node.right, depth + 1);
      if (right.value !== undefined) {
        return right;
      }

      return resolve(node.left, depth + 1);
    }

    if (t.isMemberExpression(node)) {
      return { params: [memberName(node)] };
    }

    if (t.isCallExpression(node)) {
      const inlined = functionRegistry?.inlineCall(node);
      if (inlined) {
        return resolve(inlined, depth + 1);
      }
      return { params: [calleeName(node.callee)] };
    }

    return { params: [] };
  };

  return {
    resolve: (node) => resolve(node),
    inlineCall: (node) => functionRegistry?.inlineCall(node),
    constants,
  };
}

export function collectStringConstants(program: t.File, functionRegistry?: FunctionRegistry): Map<string, string> {
  const constants = new Map<string, string>();
  let changed = true;
  let rounds = 0;

  while (changed && rounds < 5) {
    changed = false;
    rounds += 1;
    const resolver = createStringResolver(constants, functionRegistry);

    traverseAst(program, {
      VariableDeclarator(path) {
        if (!t.isIdentifier(path.node.id) || !path.node.init) {
          return;
        }

        const resolved = resolver.resolve(path.node.init);
        if (resolved.value !== undefined && constants.get(path.node.id.name) !== resolved.value) {
          constants.set(path.node.id.name, resolved.value);
          changed = true;
        }
      },
    });
  }

  return constants;
}

function placeholderFor(node: t.Node): string {
  if (t.isIdentifier(node)) {
    return `\${${node.name}}`;
  }
  if (t.isMemberExpression(node)) {
    return `\${${memberName(node)}}`;
  }
  return '${value}';
}

export function memberName(node: t.MemberExpression): string {
  const objectName = t.isMemberExpression(node.object)
    ? memberName(node.object)
    : t.isIdentifier(node.object)
      ? node.object.name
      : 'unknown';
  const propertyName = node.computed
    ? t.isStringLiteral(node.property)
      ? node.property.value
      : t.isIdentifier(node.property)
        ? node.property.name
        : 'computed'
    : t.isIdentifier(node.property)
      ? node.property.name
      : 'unknown';

  return `${objectName}.${propertyName}`;
}

export function calleeName(node: t.Node): string {
  if (t.isIdentifier(node)) {
    return node.name;
  }
  if (t.isMemberExpression(node)) {
    return memberName(node);
  }
  return 'unknown';
}

function trimLong(value: string): string {
  return value.length > MAX_STRING_LENGTH ? value.slice(0, MAX_STRING_LENGTH) : value;
}
