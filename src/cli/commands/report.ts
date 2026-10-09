import { Argv } from 'yargs';
import * as fs from 'fs';
import type { AnalysisResult } from '../../types/analysis-result.js';
import { assertAnalysisResult } from '../../types/analysis-result.js';
import { createAIProvider, type AIProviderName } from '../../adapters/ai_providers/provider_factory.js';
import { enrichRemediations } from '../../adapters/ai_providers/enrich.js';
import { renderMarkdownReport } from '../report/render-markdown.js';
import { renderDocxReport } from '../../adapters/report/docx_renderer.js';
import { allCveIds, applyThreatIntel, lookupThreatIntel, threatIntelInfo } from '../../core/threat_intel.js';
import { CacheManager } from '../../core/cache_manager.js';
import { SARIFRenderer } from '../../adapters/report/sarif_renderer.js';
import { ContextLoader } from '../../adapters/context/context_loader.js';
import { HTMLReportRenderer } from '../../adapters/report/html_renderer.js';
import { shownPath } from '../../adapters/report/escape.js';

export interface ReportPipelineOptions {
  input: string;
  format: 'html' | 'markdown' | 'json' | 'docx' | 'sarif';
  output?: string;
  aiProvider?: AIProviderName | 'none';
  aiToken?: string;
  aiBaseUrl?: string;
  aiModel?: string;
  enrichment?: boolean;
  /** Output of `hawkeye expose -o`, attached to the result as context.exposure. */
  exposure?: string;
}

export interface ReportPipelineDeps {
  createProvider?: typeof createAIProvider;
  readFile?: typeof fs.readFileSync;
}

export async function runReportPipeline(
  opts: ReportPipelineOptions,
  deps?: ReportPipelineDeps,
): Promise<string | Buffer> {
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

  if (opts.exposure) result.context = { ...result.context, exposure: ContextLoader.readExposureFile(opts.exposure) };

  // .hawkeye.yaml of the project plus the exposure detected by `hawkeye expose`, if any
  const projectPath = result.project_path || process.cwd();
  const { context, warnings: contextWarnings } = ContextLoader.forReport(projectPath, result.context?.exposure);
  contextWarnings.forEach(w => process.stderr.write(`⚠️  ${w}\n`));

  if (context) {
    process.stderr.write(`📍 Loaded context from ${context.sourceFile} (exposure: ${context.config.exposure})\n`);
  }
  // Results written before 1.3.0 hold the absolute path of the machine that ran the scan.
  if (result.project_path && !shownPath(result.project_path)) delete result.project_path;

  // Optionally enrich with CVE context (CISA KEV + FIRST EPSS)
  if (opts.enrichment) {
    const cache = new CacheManager();
    const intel = await lookupThreatIntel(allCveIds(result.results.map(f => f.vulnerability)), cache);
    cache.save();
    intel.warnings.forEach(w => process.stderr.write(`⚠️  ${w}\n`));
    applyThreatIntel(result.results, intel);
    if (result.scan) {
      // Keep the record of an earlier successful check when this one fails.
      const fresh = threatIntelInfo(intel);
      const previous = result.scan.threat_intel;
      result.scan.threat_intel = {
        kev: fresh.kev.status === 'checked' || !previous ? fresh.kev : previous.kev,
        epss: fresh.epss.status === 'checked' || !previous?.epss ? fresh.epss : previous.epss,
      };
    }
  }

  // Optionally add AI suggestions (code changes, effort, notes) to the engine's remediations
  const aiProvider = opts.aiProvider === 'none' ? null : opts.aiProvider || null;

  if (aiProvider) {
    try {
      const provider = createProviderFn(aiProvider as AIProviderName, opts.aiToken, {
        baseUrl: opts.aiBaseUrl,
        model: opts.aiModel,
      });

      if (provider) {
        const summary = await enrichRemediations(result.results, provider);
        summary.warnings.forEach(w => process.stderr.write(`⚠️  ${w}\n`));
        process.stderr.write(
          `🤖 AI suggestions added to ${summary.enriched} of ${result.results.length} findings` +
            (summary.failedBatches ? ` (${summary.failedBatches} of ${summary.batches} requests failed)` : '') +
            '\n',
        );
      }
    } catch (error) {
      process.stderr.write(`⚠️  AI enhancement failed: ${(error as Error).message}\n`);
      // Continue without AI enhancement
    }
  }

  // Render report
  let rendered: string | Buffer;

  if (opts.format === 'html') {
    // Use new HTMLReportRenderer with exposure context
    const renderer = new HTMLReportRenderer(result, context, aiProvider || undefined);
    rendered = renderer.render();
  } else if (opts.format === 'markdown') {
    rendered = renderMarkdownReport(result, {
      aiPowered: !!aiProvider,
      providerName: aiProvider || undefined,
    });
  } else if (opts.format === 'docx') {
    rendered = await renderDocxReport(result);
  } else if (opts.format === 'sarif') {
    rendered = new SARIFRenderer(result).render();
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
        choices: ['html', 'markdown', 'json', 'docx', 'sarif'],
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
      .option('exposure', {
        type: 'string',
        description: 'Exposure file written by `hawkeye expose -o`; raises the HTML score if internet-facing',
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
      exposure: argv.exposure,
    };

    try {
      const log = (m: string) => process.stderr.write(`${m}\n`);
      log(`📄 Generating ${options.format.toUpperCase()} report from ${options.input}...`);
      if (options.enrichment) log('🔍 Enriching findings with CISA KEV + FIRST EPSS...');
      if (options.aiProvider && options.aiProvider !== 'none') log(`🤖 Using AI provider: ${options.aiProvider}`);

      const rendered = await runReportPipeline(options);

      if (options.output) {
        fs.writeFileSync(options.output, rendered);
        log(`✅ Report saved to: ${options.output}`);
      } else if (typeof rendered === 'string') {
        process.stdout.write(rendered.endsWith('\n') ? rendered : `${rendered}\n`);
      } else {
        log('DOCX is binary; use --output to save it to a file');
        process.exitCode = 1;
      }
    } catch (error) {
      process.stderr.write(`❌ Report generation failed: ${(error as Error).message}\n`);
      process.exitCode = 1;
    }
  },
};
