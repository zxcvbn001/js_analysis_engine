import traverseModule, { type TraverseOptions } from '@babel/traverse';
import type { Node } from '@babel/types';

type TraverseFunction = (node: Node, visitor: TraverseOptions) => void;

const traverseFn = ((traverseModule as unknown as { default?: TraverseFunction }).default ?? traverseModule) as TraverseFunction;

export function traverseAst(node: Node, visitor: TraverseOptions): void {
  traverseFn(node, visitor);
}
