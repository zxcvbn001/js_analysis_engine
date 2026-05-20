import type { LLMSecretResult } from '../../types/llm.js';

export class SecretAnalysisCache {
  private readonly values = new Map<string, LLMSecretResult>();

  get(key: string): LLMSecretResult | undefined {
    return this.values.get(key);
  }

  set(key: string, value: LLMSecretResult): void {
    this.values.set(key, value);
  }
}
