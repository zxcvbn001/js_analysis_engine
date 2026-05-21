import { randomUUID } from 'node:crypto';
import type { AnalysisTask } from '../../types/tasks.js';
import type { AnalyzeMode } from '../../types/results.js';
import { getConfig } from '../../config/appConfig.js';
import { fetchTextContent } from '../../utils/fetchContent.js';
import { analyzeJavaScript } from './javascriptAnalyzer.js';
import { summarizeAnalysis, summarizeContent } from '../../utils/analysisSummary.js';
import { logError, logInfo } from '../../utils/logger.js';

interface SubmitTaskInput {
  url?: string;
  content?: string;
  mode: AnalyzeMode;
}

const tasks = new Map<string, AnalysisTask>();
const MAX_TASKS = 1000;

export function submitAnalysisTask(input: SubmitTaskInput): AnalysisTask {
  const now = new Date().toISOString();
  const task: AnalysisTask = {
    id: randomUUID(),
    status: 'queued',
    createdAt: now,
    updatedAt: now,
  };

  tasks.set(task.id, task);
  trimOldTasks();
  logInfo('analysis_task_queued', {
    taskId: task.id,
    url: input.url,
    mode: input.mode,
    hasContent: Boolean(input.content?.trim()),
    inputContentLength: input.content?.length ?? 0,
  });

  queueMicrotask(() => {
    runTask(task.id, input).catch((error) => {
      failTask(task.id, error instanceof Error ? error.message : 'Unknown task failure');
    });
  });

  return task;
}

export function getAnalysisTask(id: string): AnalysisTask | undefined {
  return tasks.get(id);
}

async function runTask(id: string, input: SubmitTaskInput): Promise<void> {
  const startedAt = Date.now();
  updateTask(id, { status: 'running' });
  logInfo('analysis_task_running', {
    taskId: id,
    url: input.url,
  });

  const source = input.content?.trim() ? 'content' : 'download';
  const content = source === 'content' ? input.content ?? '' : await fetchTextContent(input.url ?? '', getConfig().fetch);
  logInfo('analysis_task_content_prepared', {
    taskId: id,
    url: input.url,
    ...summarizeContent({ content, source, url: input.url }),
  });
  const result = await analyzeJavaScript({ url: input.url, content, mode: input.mode });

  if (!result.success) {
    updateTask(id, {
      status: 'failed',
      result,
      error: result.error,
    });
    logError('analysis_task_failed', {
      taskId: id,
      url: input.url,
      durationMs: Date.now() - startedAt,
      errorMessage: result.error.message,
    });
    return;
  }

  updateTask(id, {
    status: 'completed',
    result,
  });
  logInfo('analysis_task_completed', {
    taskId: id,
    url: input.url,
    durationMs: Date.now() - startedAt,
    ...summarizeAnalysis(result),
  });
}

function failTask(id: string, message: string): void {
  updateTask(id, {
    status: 'failed',
    error: { message },
    result: {
      success: false,
      error: { message },
    },
  });
  logError('analysis_task_failed', {
    taskId: id,
    errorMessage: message,
  });
}

function updateTask(id: string, patch: Partial<AnalysisTask>): void {
  const task = tasks.get(id);
  if (!task) {
    return;
  }

  tasks.set(id, {
    ...task,
    ...patch,
    updatedAt: new Date().toISOString(),
  });
}

function trimOldTasks(): void {
  if (tasks.size <= MAX_TASKS) {
    return;
  }

  const oldest = [...tasks.values()].sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  for (const task of oldest.slice(0, tasks.size - MAX_TASKS)) {
    tasks.delete(task.id);
  }
}
