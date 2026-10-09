import { Argv } from 'yargs';
import * as fs from 'fs';
import { AnalysisEngine } from '../../core/analysis_engine.js';
import { SARIFRenderer } from '../../adapters/report/sarif_renderer.js';
import { HTMLReportRenderer } from '../../adapters/report/html_renderer.js';
import { ContextLoader, type HawkeyeContext } from '../../adapters/context/context_loader.js';
import type { AnalysisResult, Severity } from '../../types/analysis-result.js';

const SEVERITIES: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export const analyzeCommand = {
  command: 'analyze <path>',
  description: 'Analyze a repository (npm, Python, Maven, Gradle) for reachable vulnerable dependencies',
  builder: (yargs: Argv) => {
    return yargs
      .positional('path', {
        describe: 'Path to the repository or project directory',
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
      .option('only', {
        type: 'string',
        description: 'Comma-separated project kinds to scan: npm,python,maven,gradle (default: all detected)',
      })
      .option('build-tool', {
        type: 'boolean',
        default: false,
        description:
          'Run mvn/gradle (or ./mvnw, ./gradlew) to resolve Java dependencies exactly. Executes the project build scripts: only for trusted repositories',
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
      })
      .option('exposure', {
        type: 'string',
        description: 'Exposure file written by `hawkeye expose -o`; raises the HTML score if internet-facing',
      });
  },

  handler: async (argv: any) => {
    const projectPath: string = argv.path;
    const log = (message: string) => process.stderr.write(`${message}\n`);

    try {
      if (!fs.existsSync(projectPath)) {
        throw new Error(`Project path not found: ${projectPath}`);
      }
      // Read before the scan so a bad file fails fast.
      const exposure = argv.exposure ? ContextLoader.readExposureFile(argv.exposure) : undefined;
      log(`📁 Analyzing ${projectPath} (level ${argv.level})`);

      const engine = new AnalysisEngine({
        projectPath,
        level: argv.level,
        includeDev: argv['include-dev'],
        kinds: parseKinds(argv.only),
        allowBuildTool: argv['build-tool'] === true,
        cacheDir: argv.cache === false ? null : argv.cache,
        onProgress: log,
      });
      const result = await engine.analyze();
      if (exposure) result.context = { exposure };

      for (const warning of result.scan?.warnings ?? []) log(`⚠️  ${warning}`);
      log(
        `✅ ${result.total_vulnerabilities} vulnerable findings, ${result.reachable_vulnerabilities} reachable ` +
            `(${result.scan?.packages_scanned} packages in ${result.scan?.projects?.length ?? 1} project(s), ` +
          `${result.scan?.files_scanned} source files)`,
      );

      const { context, warnings: contextWarnings } = ContextLoader.forReport(projectPath, result.context?.exposure);
      contextWarnings.forEach(w => log(`⚠️  ${w}`));
      const rendered = render(result, argv.format, context);
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

const KINDS = ['npm', 'python', 'maven', 'gradle'] as const;

export function parseKinds(value: unknown): Array<(typeof KINDS)[number]> | undefined {
  if (!value) return undefined;
  const kinds = String(value)
    .split(',')
    .map(k => k.trim().toLowerCase())
    .map(k => (k === 'java' ? ['maven', 'gradle'] : k === 'pypi' ? ['python'] : [k]))
    .flat();
  const bad = kinds.filter(k => !(KINDS as readonly string[]).includes(k));
  if (bad.length) throw new Error(`Unknown --only value(s): ${bad.join(', ')} (use ${KINDS.join(', ')}, java)`);
  return kinds as Array<(typeof KINDS)[number]>;
}

function render(result: AnalysisResult, format: string, context: HawkeyeContext | null): string {
  if (format === 'sarif') return new SARIFRenderer(result).render();
  if (format === 'html') {
    return new HTMLReportRenderer(result, context).render();
  }
  return JSON.stringify(result, null, 2);
}
