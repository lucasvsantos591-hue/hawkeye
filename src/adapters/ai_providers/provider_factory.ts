import type { AIProvider } from './ai_provider.interface.js';
import { ClaudeProvider } from './claude_provider.js';
import { OpenAIProvider } from './openai_provider.js';
import { GeminiProvider } from './gemini_provider.js';

export type AIProviderName = 'claude' | 'openai' | 'gemini' | 'custom' | 'none';

export interface AIProviderOptions {
  baseUrl?: string;
  model?: string;
}

export function createAIProvider(
  name: AIProviderName,
  apiKey?: string,
  options?: AIProviderOptions,
): AIProvider | null {
  if (name === 'none') {
    return null;
  }

  let key = apiKey;

  if (!key) {
    if (name === 'claude') {
      key = process.env.ANTHROPIC_API_KEY;
    } else if (name === 'openai') {
      key = process.env.OPENAI_API_KEY;
    } else if (name === 'gemini') {
      key = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
    } else if (name === 'custom') {
      key = process.env.OPENAI_API_KEY || '';
    }
  }

  switch (name) {
    case 'claude':
      return new ClaudeProvider(key || '', options);

    case 'openai':
      return new OpenAIProvider(key || '', options);

    case 'gemini':
      return new GeminiProvider(key || '', options);

    case 'custom':
      if (!options?.baseUrl) {
        throw new Error('custom provider requires --ai-base-url');
      }
      return new OpenAIProvider(key || '', options);

    default:
      throw new Error(
        `Unknown AI provider "${name}". Supported: claude, openai, gemini, custom, none.`,
      );
  }
}
