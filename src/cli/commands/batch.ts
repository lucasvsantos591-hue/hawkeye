import { Argv } from 'yargs';
import * as fs from 'fs';
import { BatchProcessor } from '../../core/batch_processor.js';

export interface BatchOptions {
  directory: string;
  level?: number;
  output?: string;
  concurrency?: number;
  verbose?: boolean;
}

export const batchCommand = {
  command: 'batch <directory>',
  description: 'Analyze multiple projects in batch mode with concurrency control',

  builder: (yargs: Argv) => {
    return yargs
      .positional('directory', {
        describe: 'Directory containing projects to analyze',
        type: 'string',
      })
      .option('level', {
        type: 'number',
        choices: [1, 2, 3],
        default: 2,
        description: 'Reachability analysis level',
      })
      .option('output', {
        alias: 'o',
        type: 'string',
        description: 'Output directory for results',
      })
      .option('concurrency', {
        type: 'number',
        default: 4,
        description: 'Maximum concurrent analyses',
      })
      .option('verbose', {
        alias: 'v',
        type: 'boolean',
        default: false,
        description: 'Verbose output',
      });
  },

  handler: async (argv: any) => {
    const options: BatchOptions = argv as BatchOptions;

    try {
      if (!fs.existsSync(options.directory)) {
        throw new Error(`Directory not found: ${options.directory}`);
      }

      process.stderr.write(
        `🔍 Starting batch analysis of: ${options.directory}\n`,
      );

      const processor = new BatchProcessor(options.concurrency || 4);
      processor.addJobsFromDirectory(options.directory);

      const result = await processor.process();

      // Output summary
      const summary = BatchProcessor.summarizeResults(result);
      console.error(summary);

      // Output results as JSON
      const output = {
        timestamp: new Date().toISOString(),
        directory: options.directory,
        ...result,
        results: Array.from(result.results.entries()).map(([name, data]) => ({
          project: name,
          success: !(data instanceof Error),
          error: data instanceof Error ? data.message : undefined,
          risk_score:
            !(data instanceof Error) ? data.overall_risk_score : undefined,
        })),
      };

      console.log(JSON.stringify(output, null, 2));

      // Save if output directory specified
      if (options.output) {
        fs.mkdirSync(options.output, { recursive: true });

        for (const [name, data] of result.results.entries()) {
          if (!(data instanceof Error)) {
            const outPath = `${options.output}/${name}-analysis.json`;
            fs.writeFileSync(outPath, JSON.stringify(data, null, 2));
          }
        }

        process.stderr.write(`📁 Results saved to: ${options.output}\n`);
      }
    } catch (error) {
      process.stderr.write(
        `❌ Batch processing failed: ${(error as Error).message}\n`,
      );
      process.exit(1);
    }
  },
};
