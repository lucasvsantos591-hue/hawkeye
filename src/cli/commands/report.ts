import { Argv } from 'yargs';
import * as fs from 'fs';
import type { AnalysisResult } from '../../types/analysis-result.js';
import { assertAnalysisResult } from '../../types/analysis-result.js';
import { createAIProvider, type AIProviderName } from '../../adapters/ai_providers/provider_factory.js';
import { renderHtmlReport } from '../report/render-html.js';
import { renderMarkdownReport } from '../report/render-markdown.js';
import { renderDocxReport } from '../../adapters/report/docx_renderer.js';
import { enrichmentService } from '../../adapters/enrichment/enrichment_service.js';
import { loadContext } from '../../adapters/context/context_loader.js';
import { createContextProcessor } from '../../adapters/context/context_processor.js';

export interface ReportPipelineOptions {
  input: string;
  format: 'html' | 'markdown' | 'json' | 'docx';
  output?: string;
  aiProvider?: AIProviderName | 'none';
  aiToken?: string;
  aiBaseUrl?: string;
  aiModel?: string;
  enrichment?: boolean;
  context?: string;
}

export interface ReportPipelineDeps {
  createProvider?: typeof createAIProvider;
  readFile?: typeof fs.readFileSync;
}

export type ReportOutput = string | Buffer;

export async function runReportPipeline(
  opts: ReportPipelineOptions,
  deps?: ReportPipelineDeps,
): Promise<ReportOutput> {
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

  // Optionally enrich with CVE context (CISA KEV + FIRST EPSS)
  if (opts.enrichment) {
    try {
      const enrichedFindings = await enrichmentService.enrichVulnerabilities(result.results);
      (result as any).enriched_results = enrichedFindings;
    } catch (error) {
      console.warn(`⚠️ Warning: CVE enrichment failed: ${(error as Error).message}`);
      // Continue without enrichment
    }
  }

  // Optionally apply infrastructure context (security gates, WAF rules, auth, etc.)
  if (opts.context) {
    try {
      const hawkeyeContext = loadContext(opts.context);
      const processor = createContextProcessor(hawkeyeContext);
      const contextualized = await processor.process(result.results);

      // Convert Map to object for JSON serialization
      const contextualizedObj: Record<string, unknown> = {};
      contextualized.forEach((value, key) => {
        contextualizedObj[key] = value;
      });
      (result as any).contextualized_findings = contextualizedObj;
      console.log(`✅ Infrastructure context applied from: ${opts.context}`);
    } catch (error) {
      console.warn(`⚠️ Warning: Context processing failed: ${(error as Error).message}`);
      // Continue without context
    }
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
  let rendered: ReportOutput;

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
  } else if (opts.format === 'docx') {
    rendered = await renderDocxReport(result);
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
        choices: ['html', 'markdown', 'json', 'docx'],
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
      })
      .option('enrichment', {
        type: 'boolean',
        default: false,
        description: 'Enrich findings with CVE context (CISA KEV + FIRST EPSS)',
      })
      .option('context', {
        type: 'string',
        description: 'Path to Hawkeye context file (YAML/JSON) for infrastructure validation',
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
      enrichment: argv.enrichment,
      context: argv.context,
    };

    try {
      console.log(`📄 Generating ${options.format.toUpperCase()} report from ${options.input}...`);

      if (options.enrichment) {
        console.log(`🔍 Enriching findings with CVE context (CISA KEV + FIRST EPSS)...`);
      }

      if (options.context) {
        console.log(`🛡️ Applying infrastructure context from: ${options.context}`);
      }

      if (options.aiProvider && options.aiProvider !== 'none') {
        console.log(`🤖 Using AI provider: ${options.aiProvider}`);
      }

      const rendered = await runReportPipeline(options);

      if (options.output) {
        if (options.format === 'docx') {
          fs.writeFileSync(options.output, rendered as Buffer);
        } else {
          fs.writeFileSync(options.output, rendered as string);
        }
        console.log(`✅ Report saved to: ${options.output}`);
      } else {
        if (options.format === 'docx') {
          console.error('❌ DOCX format requires --output (cannot write binary to stdout)');
          process.exit(1);
        } else {
          console.log(rendered);
        }
      }
    } catch (error) {
      console.error('❌ Report generation failed:', (error as Error).message);
      process.exit(1);
    }
  },
};
