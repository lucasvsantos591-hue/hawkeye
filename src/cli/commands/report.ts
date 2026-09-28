import { Argv } from 'yargs';
import * as fs from 'fs';
import type { AnalysisResult } from '../../types/analysis-result.js';
import { assertAnalysisResult } from '../../types/analysis-result.js';
import { createAIProvider, type AIProviderName } from '../../adapters/ai_providers/provider_factory.js';
import { renderHtmlReport } from '../report/render-html.js';
import { renderMarkdownReport } from '../report/render-markdown.js';

export interface ReportPipelineOptions {
  input: string;
  format: 'html' | 'markdown' | 'json';
  output?: string;
  aiProvider?: AIProviderName | 'none';
  aiToken?: string;
  aiBaseUrl?: string;
  aiModel?: string;
}

export interface ReportPipelineDeps {
  createProvider?: typeof createAIProvider;
  readFile?: typeof fs.readFileSync;
}

export async function runReportPipeline(
  opts: ReportPipelineOptions,
  deps?: ReportPipelineDeps,
): Promise<string> {
  const readFile = deps?.readFile || fs.readFileSync;
  const createProviderFn = deps?.createProvider || createAIProvider;

  // Read and validate input
  const rawInput = readFile(opts.input, 'utf-8');
  let result: AnalysisResult;
  try {
    result = assertAnalysisResult(JSON.parse(rawInput));
  } catch (error) {
    throw new Error(`Invalid analysis result JSON: ${(error as Error).message}`);
  }

  // Optionally enhance with AI
  const aiProvider = opts.aiProvider === 'none' ? null : opts.aiProvider || null;

  if (aiProvider) {
    try {
      const provider = createProviderFn(aiProvider as AIProviderName, opts.aiToken, {
        baseUrl: opts.aiBaseUrl,
        model: opts.aiModel,
      });

      if (provider) {
        const suggestions = await provider.generateRemediations(result.results);

        // Merge suggestions back into results by cve_id
        for (const suggestion of suggestions) {
          const finding = result.results.find((r) => r.vulnerability.cve_id === suggestion.cve_id);
          if (finding) {
            finding.remediation = {
              type: suggestion.type,
              description: suggestion.description,
              required_version: suggestion.required_version,
              breaking_changes: suggestion.breaking_changes,
              changes_needed: suggestion.changes_needed,
              action: suggestion.action,
              effort_estimate: suggestion.effort_estimate,
              notes: suggestion.notes,
            };
          }
        }
      }
    } catch (error) {
      console.warn(`⚠️ Warning: AI enhancement failed: ${(error as Error).message}`);
      // Continue without AI enhancement
    }
  }

  // Render report
  let rendered: string;

  if (opts.format === 'html') {
    rendered = renderHtmlReport(result, {
      aiPowered: !!aiProvider,
      providerName: aiProvider || undefined,
    });
  } else if (opts.format === 'markdown') {
    rendered = renderMarkdownReport(result, {
      aiPowered: !!aiProvider,
      providerName: aiProvider || undefined,
    });
  } else if (opts.format === 'json') {
    rendered = JSON.stringify(result, null, 2);
  } else {
    throw new Error(`Unsupported format: ${opts.format}`);
  }

  return rendered;
}

export const reportCommand = {
  command: 'report <input>',
  description: 'Generate a report from analysis results (with optional AI-powered remediations)',

  builder: (yargs: Argv) => {
    return yargs
      .positional('input', {
        describe: 'Path to analysis results JSON file',
        type: 'string',
      })
      .option('format', {
        alias: 'f',
        type: 'string',
        choices: ['html', 'markdown', 'json'],
        default: 'html',
        description: 'Output report format',
      })
      .option('output', {
        alias: 'o',
        type: 'string',
        description: 'Output file path (default: stdout)',
      })
      .option('ai-provider', {
        type: 'string',
        choices: ['claude', 'openai', 'gemini', 'custom', 'none'],
        default: 'none',
        description: 'AI provider for remediation suggestions (none = skip AI)',
      })
      .option('ai-token', {
        type: 'string',
        description: 'API token for AI provider (or set provider env var)',
      })
      .option('ai-base-url', {
        type: 'string',
        description: 'Base URL for custom OpenAI-compatible provider',
      })
      .option('ai-model', {
        type: 'string',
        description: 'Model override for AI provider',
      });
  },

  handler: async (argv: any) => {
    const options: ReportPipelineOptions = {
      input: argv.input,
      format: argv.format,
      output: argv.output,
      aiProvider: argv['ai-provider'],
      aiToken: argv['ai-token'],
      aiBaseUrl: argv['ai-base-url'],
      aiModel: argv['ai-model'],
    };

    try {
      console.log(`📄 Generating ${options.format.toUpperCase()} report from ${options.input}...`);

      if (options.aiProvider && options.aiProvider !== 'none') {
        console.log(`🤖 Using AI provider: ${options.aiProvider}`);
      }

      const rendered = await runReportPipeline(options);

      if (options.output) {
        fs.writeFileSync(options.output, rendered);
        console.log(`✅ Report saved to: ${options.output}`);
      } else {
        console.log(rendered);
      }
    } catch (error) {
      console.error('❌ Report generation failed:', (error as Error).message);
      process.exit(1);
    }
  },
};
