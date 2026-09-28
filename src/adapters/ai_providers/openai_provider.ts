import type { VulnerabilityFinding } from '../../types/analysis-result.js';
import type { AIProvider, RemediationSuggestion } from './ai_provider.interface.js';
import { buildRemediationPrompt, parseRemediationResponse } from './prompts.js';

export class OpenAIProvider implements AIProvider {
  readonly name = 'openai';

  constructor(
    private apiKey: string,
    private options: { baseUrl?: string; model?: string } = {},
  ) {
    if (!apiKey && !this.options.baseUrl) {
      throw new Error(
        'OpenAI API key is required. Set OPENAI_API_KEY environment variable or pass --ai-token',
      );
    }
  }

  async generateRemediations(findings: VulnerabilityFinding[]): Promise<RemediationSuggestion[]> {
    let OpenAI: any;
    try {
      const mod = await import('openai');
      OpenAI = mod.default;
    } catch (error) {
      throw new Error('Run "npm install openai" to use --ai-provider openai');
    }

    const client = new OpenAI({
      apiKey: this.apiKey,
      baseURL: this.options.baseUrl,
    });

    const prompt = buildRemediationPrompt(findings);
    const model = this.options.model || 'gpt-4-turbo';

    const response = await client.chat.completions.create({
      model,
      max_tokens: 4096,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error('Empty response from OpenAI API');
    }

    const suggestions = parseRemediationResponse(content, findings);
    return suggestions;
  }
}
