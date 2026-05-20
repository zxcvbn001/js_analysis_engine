import type { AnalysisResponse } from './results.js';

export type AnalysisTaskStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface AnalysisTask {
  id: string;
  status: AnalysisTaskStatus;
  createdAt: string;
  updatedAt: string;
  result?: AnalysisResponse;
  error?: {
    message: string;
  };
}
