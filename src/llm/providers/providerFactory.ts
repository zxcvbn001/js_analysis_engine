import type { LLMProvider } from '../../types/llm.js';
import { getConfig } from '../../config/appConfig.js';
import { DeepSeekProvider } from './deepSeekProvider.js';

export function createLLMProvider(): LLMProvider | undefined {
  const provider = getConfig().llm.provider.toLowerCase();
  if (provider === 'none') {
    return undefined;
  }
  if (provider === 'deepseek') {
    if (!getConfig().llm.apiKey.trim()) {
      return undefined;
    }
    return new DeepSeekProvider();
  }
  return undefined;
}
