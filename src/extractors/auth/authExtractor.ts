const authMarkers = ['authorization', 'bearer', 'jwt', 'x-token', 'token'];

export function extractAuthSignals(headers: string[], texts: string[]): string[] {
  const found = new Set<string>();

  for (const header of headers) {
    const lower = header.toLowerCase();
    if (lower === 'authorization') {
      found.add('Authorization');
    }
    if (lower.includes('token')) {
      found.add(header);
    }
  }

  for (const text of texts) {
    const lower = text.toLowerCase();
    for (const marker of authMarkers) {
      if (lower.includes(marker)) {
        found.add(marker === 'bearer' ? 'Bearer' : marker === 'jwt' ? 'JWT' : marker);
      }
    }
  }

  return [...found];
}
