import { z } from 'zod';

export const analyzeJsRequestSchema = z.object({
  url: z.string().url().optional(),
  content: z.string().optional(),
  fast_mode: z.boolean().optional(),
  mode: z.enum(['fast', 'full']).optional(),
  response_mode: z.enum(['full', 'compact']).optional(),
  async: z.boolean().optional(),
}).refine((value) => Boolean(value.content?.trim()) || Boolean(value.url?.trim()), {
  message: 'Either content or url is required',
});

export const analyzeSecretRequestSchema = z.object({
  candidate: z.string().min(1),
  context: z.string().min(1),
});

export type AnalyzeJsRequest = z.infer<typeof analyzeJsRequestSchema>;
export type AnalyzeSecretRequest = z.infer<typeof analyzeSecretRequestSchema>;
