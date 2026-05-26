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
let llmConsoleLoggerOverride: {
  enabled: boolean;
  stdout: LogStream;
  stderr: LogStream;
} | undefined;

export interface LogFields {
  [key: string]: unknown;
}

export interface LogStream {
  write(message: string): void;
}

export function logDebug(message: string, fields: LogFields = {}): void {
  writeLog('debug', message, fields);
}

export function configureFileLogger(config: AppConfig['logging']): void {
  loggingConfigOverride = config;
}

export function configureLlmConsoleLogger(config?: { enabled?: boolean; stdout?: LogStream; stderr?: LogStream }): void {
  if (!config) {
    llmConsoleLoggerOverride = undefined;
    return;
  }

  llmConsoleLoggerOverride = {
    enabled: config.enabled ?? true,
    stdout: config.stdout ?? process.stdout,
    stderr: config.stderr ?? process.stderr,
  };
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
  const now = new Date();
  const payload = {
    time: now.toISOString(),
    level,
    message,
    ...fields,
  };
  const line = formatLogLine(payload);
  const levelEnabled = levelRank[level] >= levelRank[config.level];

  if (config.fileEnabled && levelEnabled) {
    const directory = resolve(process.cwd(), config.directory);
    mkdirSync(directory, { recursive: true });

    const fileName = `${now.toISOString().slice(0, 10)}.log`;
    appendFileSync(resolve(directory, fileName), `${line}\n`, 'utf8');
  }

  if (levelEnabled && isLlmLogEvent(message)) {
    const consoleLogger = resolveLlmConsoleLogger();
    if (consoleLogger.enabled) {
      const output = level === 'error' ? consoleLogger.stderr : consoleLogger.stdout;
      output.write(`${line}\n`);
    }
  }
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

export function createPinoConsoleStream(output: NodeJS.WritableStream = process.stdout): LogStream {
  return {
    write(message: string): void {
      const line = formatPinoLine(message);
      if (!line) {
        return;
      }
      output.write(`${line}\n`);
    },
  };
}

function formatLogLine(payload: { time: string; level: LogLevel; message: string; [key: string]: unknown }): string {
  const prefix = `[${payload.level.toUpperCase()}] ${payload.time} ${payload.message}`;
  const fieldEntries = Object.entries(payload).filter(([key]) => !['time', 'level', 'message'].includes(key));
  if (fieldEntries.length === 0) {
    return prefix;
  }

  return `${prefix} ${fieldEntries.map(([key, value]) => `${key}=${formatValue(value)}`).join(' ')}`;
}

function formatValue(value: unknown): string {
  if (value === undefined) {
    return 'undefined';
  }
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}

function formatPinoLine(message: string): string {
  const trimmed = message.trim();
  if (!trimmed) {
    return '';
  }

  try {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    return formatLogLine(normalizePinoPayload(parsed));
  } catch {
    return trimmed;
  }
}

function normalizePinoPayload(payload: Record<string, unknown>): { time: string; level: LogLevel; message: string; [key: string]: unknown } {
  const normalized: { time: string; level: LogLevel; message: string; [key: string]: unknown } = {
    time: normalizePinoTime(payload.time),
    level: normalizePinoLevel(payload.level),
    message: typeof payload.msg === 'string' ? payload.msg : typeof payload.message === 'string' ? payload.message : 'log',
  };

  if (typeof payload.reqId === 'string') {
    normalized.reqId = payload.reqId;
  }

  if (isObject(payload.req)) {
    const req = payload.req as Record<string, unknown>;
    normalized.method = req.method;
    normalized.url = req.url;
    normalized.host = req.host;
    normalized.remoteAddress = req.remoteAddress;
    normalized.remotePort = req.remotePort;
  }

  if (isObject(payload.res)) {
    const res = payload.res as Record<string, unknown>;
    normalized.statusCode = res.statusCode;
  }

  if (typeof payload.responseTime === 'number') {
    normalized.responseTimeMs = Number(payload.responseTime.toFixed(2));
  }

  if (isObject(payload.err)) {
    const err = payload.err as Record<string, unknown>;
    normalized.errorName = err.type;
    normalized.errorMessage = err.message;
    normalized.errorStack = err.stack;
  }

  for (const [key, value] of Object.entries(payload)) {
    if (['level', 'time', 'pid', 'hostname', 'msg', 'message', 'v', 'reqId', 'req', 'res', 'responseTime', 'err'].includes(key)) {
      continue;
    }
    normalized[key] = value;
  }

  return normalized;
}

function normalizePinoLevel(level: unknown): LogLevel {
  if (typeof level === 'string') {
    if (level === 'debug' || level === 'info' || level === 'warn' || level === 'error') {
      return level;
    }
    if (level === 'fatal') {
      return 'error';
    }
  }

  if (typeof level === 'number') {
    if (level >= 50) {
      return 'error';
    }
    if (level >= 40) {
      return 'warn';
    }
    if (level >= 30) {
      return 'info';
    }
    return 'debug';
  }

  return 'info';
}

function normalizePinoTime(value: unknown): string {
  if (typeof value === 'number') {
    return new Date(value).toISOString();
  }
  if (typeof value === 'string' && value) {
    return value;
  }
  return new Date().toISOString();
}

function isLlmLogEvent(message: string): boolean {
  return message.startsWith('llm_') || message === 'analyze_js_llm_runtime';
}

function resolveLlmConsoleLogger(): { enabled: boolean; stdout: LogStream; stderr: LogStream } {
  if (llmConsoleLoggerOverride) {
    return llmConsoleLoggerOverride;
  }

  const env = process.env.LOG_LLM_CONSOLE;
  if (env) {
    return {
      enabled: ['1', 'true', 'yes', 'on'].includes(env.toLowerCase()),
      stdout: process.stdout,
      stderr: process.stderr,
    };
  }

  return {
    enabled: process.env.VITEST !== 'true' && process.env.NODE_ENV !== 'test',
    stdout: process.stdout,
    stderr: process.stderr,
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
