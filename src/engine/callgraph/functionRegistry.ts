import * as t from '@babel/types';
import { traverseAst } from '../traverser/traverseAst.js';

export interface FunctionSummary {
  params: t.Identifier[];
  returnExpression?: t.Expression;
}

export interface FunctionRegistry {
  get(name: string): FunctionSummary | undefined;
  inlineCall(node: t.CallExpression): t.Expression | undefined;
}

export function buildFunctionRegistry(ast: t.File): FunctionRegistry {
  const functions = new Map<string, FunctionSummary>();

  traverseAst(ast, {
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id) || !path.node.init) {
        return;
      }
      if (!t.isArrowFunctionExpression(path.node.init) && !t.isFunctionExpression(path.node.init)) {
        return;
      }

      functions.set(path.node.id.name, {
        params: identifierParams(path.node.init.params),
        returnExpression: returnedExpression(path.node.init.body),
      });
    },
    FunctionDeclaration(path) {
      if (!path.node.id) {
        return;
      }

      functions.set(path.node.id.name, {
        params: identifierParams(path.node.params),
        returnExpression: returnedExpression(path.node.body),
      });
    },
  });

  return {
    get: (name) => functions.get(name),
    inlineCall: (node) => inlineFunctionCall(node, functions),
  };
}

function inlineFunctionCall(node: t.CallExpression, functions: Map<string, FunctionSummary>): t.Expression | undefined {
  if (!t.isIdentifier(node.callee)) {
    return undefined;
  }

  const summary = functions.get(node.callee.name);
  if (!summary?.returnExpression) {
    return undefined;
  }

  const binding = bindArguments(summary.params, node.arguments);
  return substituteIdentifiers(summary.returnExpression, binding);
}

function identifierParams(params: Array<t.Identifier | t.Pattern | t.RestElement>): t.Identifier[] {
  return params.filter((param): param is t.Identifier => t.isIdentifier(param));
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

function bindArguments(params: t.Identifier[], args: Array<t.Expression | t.SpreadElement | t.ArgumentPlaceholder>): Map<string, t.Expression> {
  const binding = new Map<string, t.Expression>();
  for (let index = 0; index < params.length; index += 1) {
    const param = params[index];
    const arg = args[index];
    if (!param || !arg || !t.isExpression(arg)) {
      continue;
    }
    binding.set(param.name, arg);
  }
  return binding;
}

function substituteIdentifiers(node: t.Expression, binding: Map<string, t.Expression>): t.Expression {
  if (t.isIdentifier(node)) {
    const replacement = binding.get(node.name);
    return replacement ? t.cloneNode(replacement, true) : node;
  }

  if (t.isBinaryExpression(node)) {
    const left = t.isExpression(node.left) ? substituteIdentifiers(node.left, binding) : node.left;
    const right = t.isExpression(node.right) ? substituteIdentifiers(node.right, binding) : t.identifier('undefined');
    return t.binaryExpression(node.operator, left, right);
  }

  if (t.isTemplateLiteral(node)) {
    return t.templateLiteral(
      node.quasis.map((quasi) => t.templateElement({ raw: quasi.value.raw, cooked: quasi.value.cooked ?? quasi.value.raw }, quasi.tail)),
      node.expressions.map((expression) => (t.isExpression(expression) ? substituteIdentifiers(expression, binding) : t.identifier('undefined'))),
    );
  }

  if (t.isCallExpression(node)) {
    return t.callExpression(
      substituteCallee(node.callee, binding),
      node.arguments.map((arg) => (t.isExpression(arg) ? substituteIdentifiers(arg, binding) : arg)),
    );
  }

  if (t.isObjectExpression(node)) {
    return t.objectExpression(node.properties.map((property) => {
      if (!t.isObjectProperty(property) || !t.isExpression(property.value)) {
        return property;
      }
      const value = substituteIdentifiers(property.value, binding);
      const shorthand = property.shorthand
        && t.isIdentifier(property.key)
        && t.isIdentifier(value)
        && property.key.name === value.name;
      return t.objectProperty(property.key, value, property.computed, shorthand);
    }));
  }

  if (t.isArrayExpression(node)) {
    return t.arrayExpression(node.elements.map((element) => (t.isExpression(element) ? substituteIdentifiers(element, binding) : element)));
  }

  if (t.isConditionalExpression(node)) {
    return t.conditionalExpression(
      node.test,
      substituteIdentifiers(node.consequent, binding),
      substituteIdentifiers(node.alternate, binding),
    );
  }

  return node;
}

function substituteCallee(node: t.Expression | t.Super | t.V8IntrinsicIdentifier, binding: Map<string, t.Expression>): t.Expression | t.Super | t.V8IntrinsicIdentifier {
  if (t.isExpression(node)) {
    return substituteIdentifiers(node, binding);
  }
  return node;
}
