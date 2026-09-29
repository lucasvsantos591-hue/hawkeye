import { Argv } from 'yargs';
import * as fs from 'fs';
import * as path from 'path';
import { ExposureDetectionService } from '../../adapters/exposure-detection/index.js';
import { loadContext } from '../../adapters/context/context_loader.js';
import type { HawkeyeContext } from '../../types/context.js';

export interface AnalyzeOptions {
  path: string;
  language?: string;
  level?: number;
  format?: 'json' | 'html' | 'sarif';
  output?: string;
  cache?: string;
  verbose?: boolean;
  debug?: boolean;
  'detect-exposure'?: boolean;
  context?: string;
}

export const analyzeCommand = {
  command: 'analyze <path>',
  description: 'Analyze a project for reachable vulnerabilities',
  builder: (yargs: Argv) => {
    return yargs
      .positional('path', {
        describe: 'Path to project directory',
        type: 'string',
      })
      .option('language', {
        alias: 'l',
        type: 'string',
        choices: ['javascript', 'typescript', 'python', 'java', 'go', 'rust'],
        description: 'Programming language (auto-detect if not specified)',
      })
      .option('level', {
        type: 'number',
        choices: [1, 2, 3],
        default: 2,
        description: 'Reachability analysis level (1=imports, 2=calls, 3=data-flow)',
      })
      .option('format', {
        alias: 'f',
        type: 'string',
        choices: ['json', 'html', 'sarif'],
        default: 'json',
        description: 'Output format',
      })
      .option('output', {
        alias: 'o',
        type: 'string',
        description: 'Output file path (default: stdout)',
      })
      .option('cache', {
        type: 'string',
        default: './.vra-cache',
        description: 'Cache directory for vulnerabilities',
      })
      .option('detect-exposure', {
        type: 'boolean',
        default: false,
        description: 'Detect internet-facing exposure (DNS, SSL, HTTP)',
      })
      .option('context', {
        type: 'string',
        description: 'Path to Hawkeye context file (JSON/YAML)',
      });
  },

  handler: async (argv: any) => {
    const options: AnalyzeOptions = argv as AnalyzeOptions;

    try {
      // Validate path
      if (!fs.existsSync(options.path)) {
        throw new Error(`Project path not found: ${options.path}`);
      }

      console.log(`📁 Analyzing project: ${options.path}`);
      console.log(`🔍 Reachability level: ${options.level}`);

      // Load context if provided
      let context: HawkeyeContext = {};
      if (options.context) {
        if (!fs.existsSync(options.context)) {
          throw new Error(`Context file not found: ${options.context}`);
        }
        context = loadContext(options.context);
        console.log(`📋 Context loaded from: ${options.context}`);
      }

      // Detect exposure if requested
      if (options['detect-exposure']) {
        console.log(`\n🔍 Detecting internet-facing exposure...`);

        // Extract domain from context or derive from project name
        const domain =
          context.application?.name ||
          path.basename(options.path).replace(/[^a-zA-Z0-9-]/g, '');

        if (!domain || domain === path.basename(options.path)) {
          console.warn(
            `⚠️  No domain specified in context.application.name. Skipping exposure detection.`,
          );
        } else {
          const exposureService = new ExposureDetectionService(options.verbose);
          const exposureContext = await exposureService.detectExposure({
            domain,
            verbose: options.verbose,
          });
          context.exposure = exposureContext;
          console.log(`✓ Exposure detection complete\n`);
        }
      }

      // TODO: Implement actual analysis logic
      // This is a placeholder that will call the Dart core via FFI or subprocess

      const result = {
        project_name: path.basename(options.path),
        project_path: options.path,
        analysis_timestamp: new Date().toISOString(),
        language: options.language || 'unknown',
        context: context,
        total_vulnerabilities: 0,
        reachable_vulnerabilities: 0,
        overall_risk_score: 0,
        results: [],
      };

      console.log('✅ Analysis complete!');
      console.log(JSON.stringify(result, null, 2));

      if (options.output) {
        fs.writeFileSync(options.output, JSON.stringify(result, null, 2));
        console.log(`📄 Report saved to: ${options.output}`);
      }
    } catch (error) {
      console.error('❌ Analysis failed:', (error as Error).message);
      process.exit(1);
    }
  },
};
