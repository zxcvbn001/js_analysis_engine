export function readEnv(name: string, fallback = ''): string {
  return process.env[name] ?? fallback;
}
