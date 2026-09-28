import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createAIProvider, type AIProviderName } from '../../src/adapters/ai_providers/provider_factory';
import { ClaudeProvider } from '../../src/adapters/ai_providers/claude_provider';
import { OpenAIProvider } from '../../src/adapters/ai_providers/openai_provider';
import { GeminiProvider } from '../../src/adapters/ai_providers/gemini_provider';

describe('provider_factory', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.GEMINI_API_KEY;
    delete process.env.GOOGLE_API_KEY;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('createAIProvider', () => {
    it('should return null for "none" provider', () => {
      const provider = createAIProvider('none');
      expect(provider).toBeNull();
    });

    it('should create ClaudeProvider for "claude" with explicit token', () => {
      const provider = createAIProvider('claude', 'test-key');
      expect(provider).toBeInstanceOf(ClaudeProvider);
      expect(provider?.name).toBe('claude');
    });

    it('should create ClaudeProvider using ANTHROPIC_API_KEY env var', () => {
      process.env.ANTHROPIC_API_KEY = 'env-key';
      const provider = createAIProvider('claude');
      expect(provider).toBeInstanceOf(ClaudeProvider);
      expect(provider?.name).toBe('claude');
    });

    it('should throw for claude without API key', () => {
      expect(() => createAIProvider('claude')).toThrow('API key is required');
    });

    it('should create OpenAIProvider for "openai" with explicit token', () => {
      const provider = createAIProvider('openai', 'sk-test');
      expect(provider).toBeInstanceOf(OpenAIProvider);
      expect(provider?.name).toBe('openai');
    });

    it('should create OpenAIProvider using OPENAI_API_KEY env var', () => {
      process.env.OPENAI_API_KEY = 'sk-env';
      const provider = createAIProvider('openai');
      expect(provider).toBeInstanceOf(OpenAIProvider);
      expect(provider?.name).toBe('openai');
    });

    it('should create GeminiProvider for "gemini" with explicit token', () => {
      const provider = createAIProvider('gemini', 'test-key');
      expect(provider).toBeInstanceOf(GeminiProvider);
      expect(provider?.name).toBe('gemini');
    });

    it('should create GeminiProvider using GEMINI_API_KEY env var', () => {
      process.env.GEMINI_API_KEY = 'gemini-key';
      const provider = createAIProvider('gemini');
      expect(provider).toBeInstanceOf(GeminiProvider);
      expect(provider?.name).toBe('gemini');
    });

    it('should create GeminiProvider using GOOGLE_API_KEY as fallback', () => {
      process.env.GOOGLE_API_KEY = 'google-key';
      const provider = createAIProvider('gemini');
      expect(provider).toBeInstanceOf(GeminiProvider);
      expect(provider?.name).toBe('gemini');
    });

    it('should create OpenAIProvider for "custom" with baseUrl and token', () => {
      const provider = createAIProvider('custom', 'test-key', {
        baseUrl: 'http://localhost:8000/v1',
      });
      expect(provider).toBeInstanceOf(OpenAIProvider);
      expect(provider?.name).toBe('openai');
    });

    it('should throw for custom without baseUrl', () => {
      expect(() => createAIProvider('custom', 'test-key')).toThrow('custom provider requires --ai-base-url');
    });

    it('should throw for custom without baseUrl even with env var', () => {
      process.env.OPENAI_API_KEY = 'sk-test';
      expect(() => createAIProvider('custom')).toThrow('custom provider requires --ai-base-url');
    });

    it('should throw for unknown provider name', () => {
      expect(() => createAIProvider('unknown-provider' as AIProviderName)).toThrow(
        'Unknown AI provider "unknown-provider"',
      );
    });

    it('should accept model option', () => {
      const provider = createAIProvider('claude', 'test-key', { model: 'claude-opus' });
      expect(provider).toBeInstanceOf(ClaudeProvider);
    });

    it('should accept baseUrl option for openai', () => {
      const provider = createAIProvider('openai', 'test-key', {
        baseUrl: 'http://localhost:8000/v1',
      });
      expect(provider).toBeInstanceOf(OpenAIProvider);
    });

    it('explicit token should win over env var', () => {
      process.env.ANTHROPIC_API_KEY = 'env-key';
      const provider = createAIProvider('claude', 'explicit-key');
      expect(provider).toBeInstanceOf(ClaudeProvider);
      expect(provider?.name).toBe('claude');
    });
  });
});
