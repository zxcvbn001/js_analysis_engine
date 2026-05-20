import * as t from '@babel/types';
import { traverseAst } from '../../engine/traverser/traverseAst.js';
import type { AssetResult } from '../../types/results.js';
import { uniqueBy } from '../../utils/dedupe.js';

interface ChunkHashMap {
  index: number;
  values: Map<string, string>;
}

export function extractAssets(ast: t.File): AssetResult[] {
  const assets: AssetResult[] = [];

  traverseAst(ast, {
    ReturnStatement(path) {
      assets.push(...recoverChunkAssets(path.node.argument, 'webpack-runtime-return'));
    },
    AssignmentExpression(path) {
      assets.push(...recoverChunkAssets(path.node.right, 'webpack-runtime-assignment'));
    },
    VariableDeclarator(path) {
      assets.push(...recoverChunkAssets(path.node.init, 'webpack-runtime-variable'));
    },
  });

  return uniqueBy(assets, (asset) => `${asset.type}:${asset.url}:${asset.chunkName ?? ''}`);
}

function recoverChunkAssets(node: t.Node | null | undefined, source: string): AssetResult[] {
  if (!node) {
    return [];
  }

  const parts = flattenConcat(node);
  if (parts.length < 3) {
    return [];
  }

  const hashMaps = findChunkHashMaps(parts);
  const assets: AssetResult[] = [];

  for (const hashMap of hashMaps) {
    const nameIndex = findChunkNameIndex(parts, hashMap.index);
    const prefix = collectStaticText(parts.slice(0, nameIndex === -1 ? hashMap.index : nameIndex));
    const infix = collectStaticText(parts.slice((nameIndex === -1 ? hashMap.index : nameIndex) + 1, hashMap.index));
    const suffix = collectStaticText(parts.slice(hashMap.index + 1));
    const staticShape = `${prefix}${infix}${suffix}`;

    if (!looksLikeAssetPath(staticShape)) {
      continue;
    }

    for (const [chunkName, hash] of hashMap.values) {
      assets.push({
        url: `${prefix}${chunkName}${infix}${hash}${suffix}`,
        type: assetTypeFromSuffix(suffix),
        chunkName,
        source,
      });
    }
  }

  return assets;
}

function flattenConcat(node: t.Node): t.Node[] {
  if (t.isBinaryExpression(node) && node.operator === '+') {
    return [...flattenConcat(node.left), ...flattenConcat(node.right)];
  }

  return [node];
}

function findChunkHashMaps(parts: t.Node[]): ChunkHashMap[] {
  return parts.flatMap((part, index) => {
    if (!t.isMemberExpression(part) || !t.isObjectExpression(part.object) || !part.computed) {
      return [];
    }

    const values = objectStringMap(part.object);
    if (values.size === 0) {
      return [];
    }

    return [{ index, values }];
  });
}

function objectStringMap(object: t.ObjectExpression): Map<string, string> {
  const values = new Map<string, string>();

  for (const property of object.properties) {
    if (!t.isObjectProperty(property)) {
      continue;
    }

    const key = propertyKey(property.key);
    if (!key || !t.isStringLiteral(property.value)) {
      continue;
    }

    values.set(key, property.value.value);
  }

  return values;
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

function findChunkNameIndex(parts: t.Node[], hashMapIndex: number): number {
  for (let index = hashMapIndex - 1; index >= 0; index -= 1) {
    const part = parts[index];
    if (!isStaticString(part)) {
      return index;
    }
  }

  return -1;
}

function collectStaticText(parts: t.Node[]): string {
  return parts.map((part) => (isStaticString(part) ? part.value : '')).join('');
}

function isStaticString(node: t.Node): node is t.StringLiteral {
  return t.isStringLiteral(node);
}

function looksLikeAssetPath(shape: string): boolean {
  return /\.(?:js|css|mjs|map)$/.test(shape) || /(?:assets?|static|chunks?)\//i.test(shape);
}

function assetTypeFromSuffix(suffix: string): AssetResult['type'] {
  if (suffix.endsWith('.js') || suffix.endsWith('.mjs')) {
    return 'script';
  }
  if (suffix.endsWith('.css')) {
    return 'style';
  }
  return 'asset';
}
