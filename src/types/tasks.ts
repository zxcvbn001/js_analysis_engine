import type { AnalysisApiResponse } from './results.js';

export type AnalysisTaskStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface AnalysisTask {
  id: string;
  status: AnalysisTaskStatus;
  createdAt: string;
  updatedAt: string;
  result?: AnalysisApiResponse;
  error?: {
    message: string;
  };
}
