#!/usr/bin/env node

import { realpathSync } from 'fs';
import { fileURLToPath } from 'url';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { analyzeCommand } from './commands/analyze.js';
import { scanCommand } from './commands/scan.js';
import { reportCommand } from './commands/report.js';
import { exposeCommand } from './commands/expose.js';
import { batchCommand } from './commands/batch.js';

export async function main() {
  const argv = yargs(hideBin(process.argv))
    .command(analyzeCommand)
    .command(scanCommand)
    .command(reportCommand)
    .command(exposeCommand)
    .command(batchCommand)
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

const invokedPath = process.argv[1] ? realpathSync(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`Error: ${error.message}\n`);
    process.exitCode = 1;
  });
}
