import { describe, expect, it } from 'vitest';
import { parseJavaScript } from '../engine/parser/jsParser.js';
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
});
