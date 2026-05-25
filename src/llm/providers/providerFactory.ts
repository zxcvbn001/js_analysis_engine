import type { LLMProvider } from '../../types/llm.js';
import { getConfig } from '../../config/appConfig.js';
import { logInfo, logWarn } from '../../utils/logger.js';
import { DeepSeekProvider } from './deepSeekProvider.js';

export function createLLMProvider(): LLMProvider | undefined {
  const config = getConfig();
  const provider = config.llm.provider.toLowerCase();
  if (provider === 'none') {
    logInfo('llm_provider_disabled', {
      provider,
      reason: 'provider is none',
    });
    return undefined;
  }
  if (provider === 'deepseek') {
    if (!config.llm.apiKey.trim()) {
      logWarn('llm_provider_disabled', {
        provider,
        model: config.llm.model,
        baseUrl: config.llm.baseUrl,
        reason: 'LLM_API_KEY is not configured',
      });
      return undefined;
    }
    logInfo('llm_provider_created', {
      provider,
      model: config.llm.model,
      baseUrl: config.llm.baseUrl,
      timeoutMs: config.llm.timeoutMs,
    });
    return new DeepSeekProvider();
  }
  logWarn('llm_provider_disabled', {
    provider,
    reason: 'unsupported provider',
  });
  return undefined;
}
