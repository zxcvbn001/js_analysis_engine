const DEFAULT_RADIUS = 220;
const MAX_SNIPPET_CHARS = 2500;
const MAX_LINE_CHARS = 500;

export function buildEvidenceSnippet(options: {
  content: string;
  value?: string;
  line?: number;
  column?: number;
  lineRadius?: number;
  charRadius?: number;
  maxChars?: number;
}): string | undefined {
  const lines = options.content.split(/\r?\n/);
  const maxChars = options.maxChars ?? MAX_SNIPPET_CHARS;
  const charRadius = options.charRadius ?? DEFAULT_RADIUS;
  const lineRadius = options.lineRadius ?? 2;
  const anchor = findAnchorIndex(options.content, options.value, options.line, options.column);

  if (anchor !== undefined) {
    return sliceAroundIndex(options.content, anchor, options.value?.length ?? 0, charRadius, maxChars);
  }

  return contextAroundLines(lines, options.line, lineRadius, maxChars);
}

export function contextAroundLines(lines: string[], line?: number, radius = 2, maxChars = MAX_SNIPPET_CHARS): string | undefined {
  if (!line || lines.length === 0) {
    return undefined;
  }
  const start = Math.max(1, line - radius);
  const end = Math.min(lines.length, line + radius);
  return lines
    .slice(start - 1, end)
    .map((text, index) => `${start + index}: ${trimLine(text)}`)
    .join('\n')
    .slice(0, maxChars);
}

function findAnchorIndex(content: string, value?: string, line?: number, column?: number): number | undefined {
  if (line && column !== undefined) {
    const lineStart = indexOfLineStart(content, line);
    if (lineStart !== undefined) {
      return lineStart + column;
    }
  }

  if (value) {
    const index = content.indexOf(value);
    if (index !== -1) {
      return index;
    }
  }

  return undefined;
}

function sliceAroundIndex(content: string, index: number, valueLength: number, radius: number, maxChars: number): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(content.length, index + Math.max(valueLength, 1) + radius);
  let snippet = content.slice(start, end);

  if (start > 0) {
    snippet = `...${snippet}`;
  }
  if (end < content.length) {
    snippet = `${snippet}...`;
  }

  if (snippet.length <= maxChars) {
    return snippet;
  }

  const center = Math.min(snippet.length, radius + 3);
  const clippedStart = Math.max(0, center - Math.floor(maxChars / 2));
  const clippedEnd = Math.min(snippet.length, clippedStart + maxChars);
  let clipped = snippet.slice(clippedStart, clippedEnd);
  if (clippedStart > 0 && !clipped.startsWith('...')) {
    clipped = `...${clipped}`;
  }
  if (clippedEnd < snippet.length && !clipped.endsWith('...')) {
    clipped = `${clipped}...`;
  }
  return clipped;
}

function indexOfLineStart(content: string, targetLine: number): number | undefined {
  if (targetLine <= 1) {
    return 0;
  }

  let currentLine = 1;
  for (let index = 0; index < content.length; index += 1) {
    if (content[index] === '\n') {
      currentLine += 1;
      if (currentLine === targetLine) {
        return index + 1;
      }
    }
  }

  return undefined;
}

function trimLine(text: string): string {
  return text.length > MAX_LINE_CHARS ? `${text.slice(0, MAX_LINE_CHARS)}... [truncated ${text.length - MAX_LINE_CHARS} chars]` : text;
}
