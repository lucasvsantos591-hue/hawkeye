import { Argv } from 'yargs';
import semver from 'semver';
import type { Ecosystem } from '../../core/versions.js';
import { CacheManager } from '../../core/cache_manager.js';
import { allCveIds, epssLookup, kevLookup, lookupThreatIntel } from '../../core/threat_intel.js';
import { OsvSource, packageKey } from '../../adapters/vulnerability_sources/osv_source.js';

const ECOSYSTEMS: Record<string, Ecosystem> = { npm: 'npm', pypi: 'PyPI', python: 'PyPI', maven: 'Maven', java: 'Maven' };

export const scanCommand = {
  command: 'scan <package> <pkgVersion>',
  description: 'List known vulnerabilities for one package version (no reachability)',
  builder: (yargs: Argv) => {
    return yargs
      .positional('package', { describe: 'Package name: lodash, requests, org.yaml:snakeyaml', type: 'string' })
      .positional('pkgVersion', { describe: 'Exact version (e.g. 4.17.20)', type: 'string' })
      .option('ecosystem', {
        alias: 'e',
        type: 'string',
        choices: ['npm', 'pypi', 'maven'],
        default: 'npm',
        description: 'Package ecosystem',
      })
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
      const ecosystem = ECOSYSTEMS[String(argv.ecosystem).toLowerCase()];
      if (ecosystem === 'npm' && !semver.valid(version)) throw new Error(`"${version}" is not an exact semver version`);
      if (!/^[0-9]/.test(version)) throw new Error(`"${version}" is not an exact version`);
      if (ecosystem === 'Maven' && !name.includes(':')) throw new Error('Maven packages are groupId:artifactId');
      const cache = new CacheManager();
      const ref = { ecosystem, name, version };
      const advisories = (await new OsvSource(cache).findAdvisories([ref])).get(packageKey(ref)) ?? [];
      const intel = await lookupThreatIntel(allCveIds(advisories), cache);
      cache.save();
      intel.warnings.forEach(w => process.stderr.write(`⚠️  ${w}\n`));

      const vulnerabilities = advisories.map(a => {
        const kev = kevLookup([a.cve_id, ...a.aliases], intel.kev);
        const epss = epssLookup([a.cve_id, ...a.aliases], intel.epss);
        return {
        id: a.id,
        cve_id: a.cve_id,
        severity: a.severity,
        summary: a.summary,
        fixed_version: a.fixed_version ?? null,
        epss_score: epss.score?.score ?? null,
        epss_status: epss.status,
        in_cisa_kev: kev.status === 'listed',
        kev_status: kev.status,
        url: a.url,
        };
      });

      if (argv.format === 'table') {
        process.stderr.write(`${name}@${version}: ${vulnerabilities.length} known vulnerabilities\n`);
        console.table(vulnerabilities.map(({ summary, url, ...row }) => row));
      } else {
        process.stdout.write(`${JSON.stringify({ package: name, version, ecosystem, vulnerabilities }, null, 2)}\n`);
      }
    } catch (error) {
      process.stderr.write(`❌ Scan failed: ${(error as Error).message}\n`);
      process.exitCode = 1;
    }
  },
};
