import { Argv } from 'yargs';
import semver from 'semver';
import { CacheManager } from '../../core/cache_manager.js';
import { lookupThreatIntel } from '../../core/threat_intel.js';
import { OsvSource } from '../../adapters/vulnerability_sources/osv_source.js';

export const scanCommand = {
  command: 'scan <package> <pkgVersion>',
  description: 'List known vulnerabilities for one npm package version (no reachability)',
  builder: (yargs: Argv) => {
    return yargs
      .positional('package', { describe: 'npm package name (e.g. lodash)', type: 'string' })
      .positional('pkgVersion', { describe: 'Exact version (e.g. 4.17.20)', type: 'string' })
      .option('format', {
        alias: 'f',
        type: 'string',
        choices: ['json', 'table'],
        default: 'json',
      });
  },

  handler: async (argv: any) => {
    const name = String(argv.package);
    const version = String(argv.pkgVersion);
    try {
      if (!semver.valid(version)) throw new Error(`"${version}" is not an exact semver version`);
      const cache = new CacheManager();
      const advisories = (await new OsvSource(cache).findAdvisories([{ name, version }])).get(`${name}@${version}`) ?? [];
      const intel = await lookupThreatIntel(advisories.map(a => a.cve_id), cache);
      cache.save();
      intel.warnings.forEach(w => process.stderr.write(`⚠️  ${w}\n`));

      const vulnerabilities = advisories.map(a => ({
        id: a.id,
        cve_id: a.cve_id,
        severity: a.severity,
        summary: a.summary,
        fixed_version: a.fixed_version ?? null,
        epss_score: intel.epss.get(a.cve_id)?.score ?? null,
        in_cisa_kev: intel.kev.has(a.cve_id),
        url: a.url,
      }));

      if (argv.format === 'table') {
        process.stderr.write(`${name}@${version}: ${vulnerabilities.length} known vulnerabilities\n`);
        console.table(vulnerabilities.map(({ summary, url, ...row }) => row));
      } else {
        process.stdout.write(`${JSON.stringify({ package: name, version, ecosystem: 'npm', vulnerabilities }, null, 2)}\n`);
      }
    } catch (error) {
      process.stderr.write(`❌ Scan failed: ${(error as Error).message}\n`);
      process.exitCode = 1;
    }
  },
};
