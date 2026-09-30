import { Argv } from 'yargs';
import * as fs from 'fs';
import { AnalysisEngine } from '../../core/analysis_engine.js';

export interface AnalyzeOptions {
  path: string;
  language?: string;
  level?: number;
  format?: 'json' | 'html' | 'sarif';
  output?: string;
  cache?: string;
  verbose?: boolean;
  debug?: boolean;
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
      });
  },

  handler: async (argv: any) => {
    const options: AnalyzeOptions = argv as AnalyzeOptions;

    try {
      // Validate path
      if (!fs.existsSync(options.path)) {
        throw new Error(`Project path not found: ${options.path}`);
      }

      // Status messages go to stderr
      process.stderr.write(`📁 Analyzing project: ${options.path}\n`);
      process.stderr.write(`🔍 Reachability level: ${options.level}\n`);

      // Run actual analysis
      const engine = new AnalysisEngine({
        projectPath: options.path,
        level: (options.level as 1 | 2 | 3) || 2,
        language: options.language,
      });

      process.stderr.write(`⏳ Running analysis...\n`);
      const result = await engine.analyze();

      process.stderr.write(
        `✅ Analysis complete! Found ${result.total_vulnerabilities} vulnerabilities ` +
        `(${result.reachable_vulnerabilities} reachable)\n`
      );

      // JSON output goes to stdout (clean, no status messages)
      console.log(JSON.stringify(result, null, 2));

      if (options.output) {
        fs.writeFileSync(options.output, JSON.stringify(result, null, 2));
        process.stderr.write(`📄 Report saved to: ${options.output}\n`);
      }
    } catch (error) {
      process.stderr.write(`❌ Analysis failed: ${(error as Error).message}\n`);
      process.exit(1);
    }
  },
};
