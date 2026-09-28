#!/usr/bin/env node

import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { analyzeCommand } from './commands/analyze.js';
import { scanCommand } from './commands/scan.js';
import { reportCommand } from './commands/report.js';

export async function main() {
  const argv = yargs(hideBin(process.argv))
    .command(analyzeCommand)
    .command(scanCommand)
    .command(reportCommand)
    .option('verbose', {
      alias: 'v',
      type: 'boolean',
      description: 'Enable verbose output',
      default: false,
    })
    .option('debug', {
      type: 'boolean',
      description: 'Enable debug output',
      default: false,
    })
    .help()
    .alias('help', 'h')
    .version()
    .alias('version', 'V')
    .strict()
    .parseAsync();

  return argv;
}

// For ESM module
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('Error:', error.message);
    process.exit(1);
  });
}
