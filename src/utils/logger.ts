import { mkdirSync, appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { getConfig, type AppConfig } from '../config/appConfig.js';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const levelRank: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

let loggingConfigOverride: AppConfig['logging'] | undefined;

export interface LogFields {
  [key: string]: unknown;
}

export function logDebug(message: string, fields: LogFields = {}): void {
  writeLog('debug', message, fields);
}

export function configureFileLogger(config: AppConfig['logging']): void {
  loggingConfigOverride = config;
}

export function logInfo(message: string, fields: LogFields = {}): void {
  writeLog('info', message, fields);
}

export function logWarn(message: string, fields: LogFields = {}): void {
  writeLog('warn', message, fields);
}

export function logError(message: string, fields: LogFields = {}): void {
  writeLog('error', message, fields);
}

function writeLog(level: LogLevel, message: string, fields: LogFields): void {
  const config = loggingConfigOverride ?? getConfig().logging;
  if (!config.fileEnabled || levelRank[level] < levelRank[config.level]) {
    return;
  }

  const directory = resolve(process.cwd(), config.directory);
  mkdirSync(directory, { recursive: true });

  const now = new Date();
  const fileName = `${now.toISOString().slice(0, 10)}.log`;
  const line = JSON.stringify({
    time: now.toISOString(),
    level,
    message,
    ...fields,
  });

  appendFileSync(resolve(directory, fileName), `${line}\n`, 'utf8');
}

export function errorFields(error: unknown): LogFields {
  if (error instanceof Error) {
    return {
      errorName: error.name,
      errorMessage: error.message,
      errorStack: error.stack,
      errorCause: formatCause(error.cause),
    };
  }

  return {
    errorMessage: String(error),
  };
}

function formatCause(cause: unknown): unknown {
  if (cause instanceof Error) {
    return {
      name: cause.name,
      message: cause.message,
    };
  }
  return cause;
}
