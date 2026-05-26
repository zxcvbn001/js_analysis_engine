import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'zod';

const llmConfigSchema = z.object({
  provider: z.string(),
  model: z.string(),
  apiKey: z.string(),
  baseUrl: z.string(),
  timeoutMs: z.number().int().min(1000).max(120000),
  logPrompts: z.boolean(),
  logResponses: z.boolean(),
  logRawPayloads: z.boolean(),
  reviewSecrets: z.boolean(),
  reviewRiskCandidates: z.boolean(),
  allowedSecretTypes: z.array(z.string().min(1)),
  allowedRiskCategories: z.array(z.string().min(1)),
});

const configSchema = z.object({
  server: z.object({
    host: z.string(),
    port: z.number().int().min(1).max(65535),
    logLevel: z.string(),
    bodyLimitMb: z.number().int().min(1).max(200),
  }),
  fetch: z.object({
    timeoutMs: z.number().int().min(1000).max(120000),
    maxBytes: z.number().int().min(1024).max(100 * 1024 * 1024),
  }),
  logging: z.object({
    fileEnabled: z.boolean(),
    directory: z.string(),
    level: z.enum(['debug', 'info', 'warn', 'error']),
  }),
  auth: z.object({
    enabled: z.boolean(),
    headerName: z.string().min(1),
    apiKeys: z.array(z.string().min(1)),
  }),
  llm: llmConfigSchema,
});

export type AppConfig = z.infer<typeof configSchema>;

const defaultConfig: AppConfig = {
  server: {
    host: '0.0.0.0',
    port: 3000,
    logLevel: 'info',
    bodyLimitMb: 20,
  },
  fetch: {
    timeoutMs: 10000,
    maxBytes: 10 * 1024 * 1024,
  },
  logging: {
    fileEnabled: true,
    directory: 'logs',
    level: 'info',
  },
  auth: {
    enabled: false,
    headerName: 'x-api-key',
    apiKeys: [],
  },
  llm: {
    provider: 'deepseek',
    model: 'deepseek-v4-flash',
    apiKey: '',
    baseUrl: 'https://api.deepseek.com',
    timeoutMs: 30000,
    logPrompts: true,
    logResponses: true,
    logRawPayloads: false,
    reviewSecrets: true,
    reviewRiskCandidates: true,
    allowedSecretTypes: [],
    allowedRiskCategories: [],
  },
};

let cachedConfig: AppConfig | undefined;

export function getConfig(): AppConfig {
  if (!cachedConfig) {
    cachedConfig = loadConfig();
  }
  return cachedConfig;
}

export function loadConfig(): AppConfig {
  const configFile = process.env.CONFIG_FILE ?? 'config/config.json';
  const fileConfig = readConfigFile(configFile);
  const merged = mergeConfig(defaultConfig, fileConfig);
  const overridden = applyEnvOverrides(merged);

  return configSchema.parse(overridden);
}

export function resetConfigForTests(): void {
  cachedConfig = undefined;
}

function readConfigFile(filePath: string): Partial<AppConfig> {
  const absolutePath = resolve(process.cwd(), filePath);
  if (!existsSync(absolutePath)) {
    return {};
  }

  const raw = readFileSync(absolutePath, 'utf8');
  return JSON.parse(raw) as Partial<AppConfig>;
}

function mergeConfig(base: AppConfig, override: Partial<AppConfig>): AppConfig {
  return {
    server: { ...base.server, ...override.server },
    fetch: { ...base.fetch, ...override.fetch },
    logging: { ...base.logging, ...override.logging },
    auth: { ...base.auth, ...override.auth },
    llm: { ...base.llm, ...override.llm },
  };
}

function applyEnvOverrides(config: AppConfig): AppConfig {
  return {
    server: {
      ...config.server,
      host: process.env.HOST ?? config.server.host,
      port: readNumberEnv('PORT', config.server.port),
      logLevel: process.env.LOG_LEVEL ?? config.server.logLevel,
      bodyLimitMb: readNumberEnv('BODY_LIMIT_MB', config.server.bodyLimitMb),
    },
    auth: {
      ...config.auth,
      enabled: readBooleanEnv('API_AUTH_ENABLED', config.auth.enabled),
      headerName: process.env.API_KEY_HEADER ?? config.auth.headerName,
      apiKeys: readApiKeys(config.auth.apiKeys),
    },
    fetch: {
      ...config.fetch,
      timeoutMs: readNumberEnv('FETCH_TIMEOUT_MS', config.fetch.timeoutMs),
      maxBytes: readNumberEnv('FETCH_MAX_BYTES', config.fetch.maxBytes),
    },
    logging: {
      ...config.logging,
      fileEnabled: readBooleanEnv('LOG_FILE_ENABLED', config.logging.fileEnabled),
      directory: process.env.LOG_DIR ?? config.logging.directory,
      level: readLogLevelEnv('LOG_FILE_LEVEL', config.logging.level),
    },
    llm: {
      ...config.llm,
      provider: process.env.LLM_PROVIDER ?? config.llm.provider,
      model: process.env.LLM_MODEL ?? config.llm.model,
      apiKey: process.env.LLM_API_KEY ?? config.llm.apiKey,
      baseUrl: process.env.LLM_BASE_URL ?? config.llm.baseUrl,
      timeoutMs: readNumberEnv('LLM_TIMEOUT_MS', config.llm.timeoutMs),
      logPrompts: readBooleanEnv('LLM_LOG_PROMPTS', config.llm.logPrompts),
      logResponses: readBooleanEnv('LLM_LOG_RESPONSES', config.llm.logResponses),
      logRawPayloads: readBooleanEnv('LLM_LOG_RAW_PAYLOADS', config.llm.logRawPayloads),
      reviewSecrets: readBooleanEnv('LLM_REVIEW_SECRETS', config.llm.reviewSecrets),
      reviewRiskCandidates: readBooleanEnv('LLM_REVIEW_RISK_CANDIDATES', config.llm.reviewRiskCandidates),
      allowedSecretTypes: readCsvEnv('LLM_ALLOWED_SECRET_TYPES', config.llm.allowedSecretTypes),
      allowedRiskCategories: readCsvEnv('LLM_ALLOWED_RISK_CATEGORIES', config.llm.allowedRiskCategories),
    },
  };
}

function readLogLevelEnv(name: string, fallback: AppConfig['logging']['level']): AppConfig['logging']['level'] {
  const raw = process.env[name];
  if (raw === 'debug' || raw === 'info' || raw === 'warn' || raw === 'error') {
    return raw;
  }
  return fallback;
}

function readNumberEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  const value = Number(raw);
  return Number.isFinite(value) ? value : fallback;
}

function readBooleanEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
}

function readApiKeys(fallback: string[]): string[] {
  const raw = process.env.API_KEYS ?? process.env.API_KEY;
  if (!raw) {
    return fallback;
  }

  return parseCsv(raw);
}

function readCsvEnv(name: string, fallback: string[]): string[] {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  return parseCsv(raw);
}

function parseCsv(raw: string): string[] {
  return raw
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}
