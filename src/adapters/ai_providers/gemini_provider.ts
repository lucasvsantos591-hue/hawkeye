import type { VulnerabilityFinding } from '../../types/analysis-result.js';
import type { AIProvider, RemediationSuggestion } from './ai_provider.interface.js';
import { buildRemediationPrompt, parseRemediationResponse } from './prompts.js';

export class GeminiProvider implements AIProvider {
  readonly name = 'gemini';

  constructor(
    private apiKey: string,
    private options: { baseUrl?: string; model?: string } = {},
  ) {
    if (!apiKey) {
      throw new Error(
        'Gemini API key is required. Set GEMINI_API_KEY or GOOGLE_API_KEY environment variable or pass --ai-token',
      );
    }
  }

  async generateRemediations(findings: VulnerabilityFinding[]): Promise<RemediationSuggestion[]> {
    let GoogleGenerativeAI: any;
    try {
      const mod = await import('@google/generative-ai');
      GoogleGenerativeAI = mod.GoogleGenerativeAI;
    } catch (error) {
      throw new Error('Run "npm install @google/generative-ai" to use --ai-provider gemini');
    }

    const client = new GoogleGenerativeAI(this.apiKey);
    const model = this.options.model || 'gemini-pro';

    const genModel = client.getGenerativeModel({ model });
    const prompt = buildRemediationPrompt(findings);

    const result = await genModel.generateContent(prompt);
    const response = await result.response;
    const content = response.text();

    if (!content) {
      throw new Error('Empty response from Gemini API');
    }

    const suggestions = parseRemediationResponse(content, findings);
    return suggestions;
  }
}
