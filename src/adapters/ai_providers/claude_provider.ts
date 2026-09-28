import type { VulnerabilityFinding } from '../../types/analysis-result.js';
import type { AIProvider, RemediationSuggestion } from './ai_provider.interface.js';
import { buildRemediationPrompt, parseRemediationResponse } from './prompts.js';

export class ClaudeProvider implements AIProvider {
  readonly name = 'claude';

  constructor(
    private apiKey: string,
    private options: { baseUrl?: string; model?: string } = {},
  ) {
    if (!apiKey) {
      throw new Error(
        'Claude API key is required. Set ANTHROPIC_API_KEY environment variable or pass --ai-token',
      );
    }
  }

  async generateRemediations(findings: VulnerabilityFinding[]): Promise<RemediationSuggestion[]> {
    let Anthropic: any;
    try {
      const mod = await import('@anthropic-ai/sdk');
      Anthropic = mod.default;
    } catch (error) {
      throw new Error('Run "npm install @anthropic-ai/sdk" to use --ai-provider claude');
    }

    const client = new Anthropic({
      apiKey: this.apiKey,
      baseURL: this.options.baseUrl,
    });

    const prompt = buildRemediationPrompt(findings);
    const model = this.options.model || 'claude-sonnet-5-5';

    const message = await client.messages.create({
      model,
      max_tokens: 4096,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    });

    const content = message.content[0];
    if (content.type !== 'text') {
      throw new Error('Unexpected response type from Claude API');
    }

    const suggestions = parseRemediationResponse(content.text, findings);
    return suggestions;
  }
}
