import { describe, expect, it } from 'vitest';
import { parseJavaScript } from '../engine/parser/jsParser.js';
import { buildFunctionRegistry } from '../engine/callgraph/functionRegistry.js';
import { collectStringConstants, createStringResolver } from '../engine/propagation/stringResolver.js';
import * as t from '@babel/types';

describe('string propagation', () => {
  it('resolves binary and template string constants', () => {
    const ast = parseJavaScript(`
      const API = '/api';
      const USER = '/user';
      const path = API + USER;
      const item = \`${'${API}'}/item/${'${id}'}\`;
    `);

    const constants = collectStringConstants(ast);
    expect(constants.get('path')).toBe('/api/user');

    const declaration = ast.program.body.find((statement) => t.isVariableDeclaration(statement) && statement.declarations[0]?.id.type === 'Identifier' && statement.declarations[0].id.name === 'item');
    const init = t.isVariableDeclaration(declaration) ? declaration.declarations[0]?.init : undefined;
    const resolved = createStringResolver(constants).resolve(init);

    expect(resolved.value).toBe('/api/item/${id}');
    expect(resolved.params).toContain('id');
  });

  it('inlines simple returned helper calls during resolution', () => {
    const ast = parseJavaScript(`
      function pathFor(id) {
        return '/api/user/' + id;
      }
      const finalPath = pathFor(userId);
    `);

    const registry = buildFunctionRegistry(ast);
    const constants = collectStringConstants(ast, registry);
    const declaration = ast.program.body.find((statement) => t.isVariableDeclaration(statement) && statement.declarations[0]?.id.type === 'Identifier' && statement.declarations[0].id.name === 'finalPath');
    const init = t.isVariableDeclaration(declaration) ? declaration.declarations[0]?.init : undefined;
    const resolved = createStringResolver(constants, registry).resolve(init);

    expect(resolved.value).toBe('/api/user/${userId}');
    expect(resolved.params).toContain('userId');
  });
});
