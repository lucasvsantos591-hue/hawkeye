import { Argv } from 'yargs';
import * as fs from 'fs';
import { AnalysisEngine } from '../../core/analysis_engine.js';
import { SARIFRenderer } from '../../adapters/report/sarif_renderer.js';
import { HTMLReportRenderer } from '../../adapters/report/html_renderer.js';
import { ContextLoader } from '../../adapters/context/context_loader.js';
import type { AnalysisResult, Severity } from '../../types/analysis-result.js';

const SEVERITIES: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export const analyzeCommand = {
  command: 'analyze <path>',
  description: 'Analyze a JavaScript/TypeScript project for reachable vulnerable dependencies',
  builder: (yargs: Argv) => {
    return yargs
      .positional('path', {
        describe: 'Path to project directory (must contain package.json)',
        type: 'string',
      })
      .option('level', {
        type: 'number',
        choices: [1, 2, 3],
        default: 2,
        description: 'Reachability level (1=imported, 2=imported bindings are used; 3 falls back to 2)',
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
        description: 'Write output to this file instead of stdout',
      })
      .option('include-dev', {
        type: 'boolean',
        default: false,
        description: 'Also report vulnerabilities in dev-only dependencies',
      })
      .option('cache', {
        type: 'string',
        description: 'Cache directory for advisory data (default: ~/.cache/hawkeye; --no-cache disables)',
      })
      .option('fail-on', {
        type: 'string',
        choices: ['low', 'medium', 'high', 'critical'],
        description: 'Exit with code 2 if a reachable finding at or above this severity exists',
      });
  },

  handler: async (argv: any) => {
    const projectPath: string = argv.path;
    const log = (message: string) => process.stderr.write(`${message}\n`);

    try {
      if (!fs.existsSync(projectPath)) {
        throw new Error(`Project path not found: ${projectPath}`);
      }
      log(`📁 Analyzing ${projectPath} (level ${argv.level})`);

      const engine = new AnalysisEngine({
        projectPath,
        level: argv.level,
        includeDev: argv['include-dev'],
        cacheDir: argv.cache === false ? null : argv.cache,
        onProgress: log,
      });
      const result = await engine.analyze();

      for (const warning of result.scan?.warnings ?? []) log(`⚠️  ${warning}`);
      log(
        `✅ ${result.total_vulnerabilities} vulnerable findings, ${result.reachable_vulnerabilities} reachable ` +
          `(${result.scan?.packages_scanned} packages, ${result.scan?.files_scanned} source files)`,
      );

      const rendered = render(result, argv.format);
      if (argv.output) {
        fs.writeFileSync(argv.output, rendered);
        log(`📄 Saved to ${argv.output}`);
      } else {
        process.stdout.write(rendered.endsWith('\n') ? rendered : `${rendered}\n`);
      }

      if (argv['fail-on']) {
        const threshold = SEVERITIES.indexOf(String(argv['fail-on']).toUpperCase() as Severity);
        const blocking = result.results.filter(
          f => f.is_reachable && SEVERITIES.indexOf(f.vulnerability.severity) >= threshold,
        );
        if (blocking.length) {
          log(`❌ ${blocking.length} reachable finding(s) at or above ${argv['fail-on']}`);
          process.exitCode = 2;
        }
      }
    } catch (error) {
      log(`❌ Analysis failed: ${(error as Error).message}`);
      process.exitCode = 1;
    }
  },
};

function render(result: AnalysisResult, format: string): string {
  if (format === 'sarif') return new SARIFRenderer(result).render();
  if (format === 'html') {
    return new HTMLReportRenderer(result, ContextLoader.loadContext(result.project_path ?? '.')).render();
  }
  return JSON.stringify(result, null, 2);
}
