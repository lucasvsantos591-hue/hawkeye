import * as path from 'path';
import semver from 'semver';
import { readDependencyInventory, type InstalledPackage } from './dependency_inventory.js';
import { buildImportIndex, type ImportIndex, type PackageUsage } from './import_index.js';
import { CacheManager, defaultCacheDir } from './cache_manager.js';
import { lookupThreatIntel } from './threat_intel.js';
import { OsvSource, type Advisory } from '../adapters/vulnerability_sources/osv_source.js';
import type {
  AnalysisResult,
  Remediation,
  Severity,
  VulnerabilityFinding,
} from '../types/analysis-result.js';

export const TOOL_VERSION = '0.2.0';

export interface AnalysisEngineOptions {
  projectPath: string;
  level?: 1 | 2 | 3;
  language?: string;
  includeDev?: boolean;
  /** Cache directory for remote data; `null` disables the cache. */
  cacheDir?: string | null;
  onProgress?: (message: string) => void;
}

interface Reachability {
  isReachable: boolean;
  level: 1 | 2;
  confidence: number;
  reason: string;
  usage?: PackageUsage;
  via?: string;
}

const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

export class AnalysisEngine {
  private readonly projectPath: string;
  private readonly level: 1 | 2 | 3;
  private readonly includeDev: boolean;
  private readonly cacheDir: string | null;
  private readonly progress: (message: string) => void;

  constructor(options: AnalysisEngineOptions) {
    this.projectPath = path.resolve(options.projectPath);
    this.level = options.level ?? 2;
    this.includeDev = options.includeDev ?? false;
    this.cacheDir = options.cacheDir === undefined ? defaultCacheDir() : options.cacheDir;
    this.progress = options.onProgress ?? (() => {});
  }

  async analyze(): Promise<AnalysisResult> {
    const warnings: string[] = [];
    if (this.level === 3) {
      warnings.push('Level 3 (data-flow) is not implemented yet; results use level 2 (usage) analysis.');
    }

    const inventory = readDependencyInventory(this.projectPath);
    warnings.push(...inventory.warnings);
    const packages = inventory.packages.filter(p => this.includeDev || !p.dev);
    this.progress(
      `📦 ${packages.length} installed packages from ${inventory.source}` +
        (this.includeDev ? '' : ` (${inventory.packages.length - packages.length} dev-only skipped)`),
    );

    const cache = new CacheManager(this.cacheDir);
    this.progress('🔎 Querying OSV.dev advisories...');
    const advisories = await new OsvSource(cache).findAdvisories(packages);

    this.progress('🧭 Indexing imports in project source...');
    const index = buildImportIndex(this.projectPath);
    if (index.parseErrors.length) {
      warnings.push(`${index.parseErrors.length} source files could not be parsed (e.g. ${index.parseErrors[0]})`);
    }

    const findings: VulnerabilityFinding[] = [];
    for (const pkg of packages) {
      const pkgAdvisories = advisories.get(`${pkg.name}@${pkg.version}`);
      if (!pkgAdvisories) continue;
      const reach = this.reachability(pkg, index);
      for (const advisory of pkgAdvisories) findings.push(buildFinding(pkg, advisory, reach));
    }

    this.progress(`🌐 Enriching ${findings.length} findings with EPSS and CISA KEV...`);
    const intel = await lookupThreatIntel(findings.map(f => f.vulnerability.cve_id), cache);
    warnings.push(...intel.warnings);
    for (const finding of findings) {
      const epss = intel.epss.get(finding.vulnerability.cve_id);
      if (epss) {
        finding.vulnerability.epss_score = epss.score;
        finding.vulnerability.epss_percentile = epss.percentile;
      }
      finding.vulnerability.is_exploited_in_wild = intel.kev.has(finding.vulnerability.cve_id);
    }
    cache.save();

    findings.sort(compareFindings);
    const reachable = findings.filter(f => f.is_reachable);

    return {
      schema_version: '1.1.0',
      generated_at: new Date().toISOString(),
      project_name: path.basename(this.projectPath),
      project_path: this.projectPath,
      total_vulnerabilities: findings.length,
      reachable_vulnerabilities: reachable.length,
      overall_risk_score: riskScore(reachable),
      summary: {
        critical_reachable: reachable.filter(f => f.vulnerability.severity === 'CRITICAL').length,
        high_reachable: reachable.filter(f => f.vulnerability.severity === 'HIGH').length,
        medium_reachable: reachable.filter(f => f.vulnerability.severity === 'MEDIUM').length,
        false_positives_filtered: findings.length - reachable.length,
      },
      results: findings,
      scan: {
        tool_version: TOOL_VERSION,
        vulnerability_source: 'OSV.dev (GitHub Advisory Database, npm)',
        dependency_source: inventory.source,
        packages_scanned: packages.length,
        files_scanned: index.filesScanned,
        include_dev: this.includeDev,
        warnings,
      },
    };
  }

  private reachability(pkg: InstalledPackage, index: ImportIndex): Reachability {
    if (pkg.direct) return this.directReachability(pkg.name, index);

    if (pkg.via.length === 0) {
      return {
        isReachable: true,
        level: 1,
        confidence: 30,
        reason: 'Transitive dependency; could not resolve which direct dependency pulls it in, so it is treated as reachable.',
      };
    }
    const viaResults = pkg.via.map(name => ({ name, reach: this.directReachability(name, index) }));
    const hit = viaResults.find(v => v.reach.isReachable);
    if (hit) {
      return {
        ...hit.reach,
        confidence: Math.min(hit.reach.confidence, 60),
        via: hit.name,
        reason:
          `Transitive dependency of ${hit.name}, which your code uses. ` +
          'Whether the vulnerable code path inside it is exercised is not verified.',
      };
    }
    return {
      isReachable: false,
      level: 1,
      confidence: 60,
      reason: `Transitive dependency pulled in only by ${pkg.via.join(', ')}, none of which is imported by project source.`,
    };
  }

  private directReachability(name: string, index: ImportIndex): Reachability {
    const usage = index.get(name);
    if (!usage || (usage.files.length === 0 && usage.testFiles.length === 0)) {
      return {
        isReachable: false,
        level: 1,
        confidence: 70,
        reason:
          'Declared dependency but never imported in project source. It may still be loaded indirectly ' +
          '(framework plugin, config string, CLI script).',
      };
    }
    if (usage.files.length === 0) {
      return {
        isReachable: false,
        level: 1,
        confidence: 80,
        usage,
        reason: `Only imported from test files (${usage.testFiles.slice(0, 3).join(', ')}).`,
      };
    }
    if (usage.typeOnly) {
      return {
        isReachable: false,
        level: 1,
        confidence: 90,
        usage,
        reason: 'Only type imports, which are erased at compile time.',
      };
    }
    if (this.level === 1) {
      return { isReachable: true, level: 1, confidence: 60, usage, reason: `Imported in ${usage.files.length} file(s).` };
    }
    if (!usage.used) {
      return {
        isReachable: false,
        level: 2,
        confidence: 70,
        usage,
        reason: 'Imported, but the imported bindings are never referenced.',
      };
    }
    const members = usage.members.length ? ` Uses: ${usage.members.slice(0, 8).join(', ')}.` : '';
    return {
      isReachable: true,
      level: 2,
      confidence: 80,
      usage,
      reason: `Used in ${usage.files.length} file(s).${members}`,
    };
  }
}

function buildFinding(pkg: InstalledPackage, advisory: Advisory, reach: Reachability): VulnerabilityFinding {
  const usage = reach.usage;
  return {
    vulnerability: {
      cve_id: advisory.cve_id,
      advisory_id: advisory.id,
      aliases: advisory.aliases,
      summary: advisory.summary,
      advisory_url: advisory.url,
      package: pkg.name,
      current_version: pkg.version,
      affected_versions: advisory.affected_ranges,
      fixed_version: advisory.fixed_version,
      severity: advisory.severity,
      cvss_vector: advisory.cvss_vector,
      dependency_type: pkg.direct ? 'direct' : 'transitive',
      introduced_via: pkg.via,
      is_dev: pkg.dev,
    },
    is_reachable: reach.isReachable,
    reachability_level: reach.level,
    confidence: reach.confidence,
    call_chain:
      reach.isReachable && usage?.sites.length
        ? { entry_point: usage.sites[0], path: reach.via ? [reach.via, pkg.name] : [pkg.name] }
        : undefined,
    reason: reach.reason,
    evidence: usage ? { files: usage.files.slice(0, 20), members: usage.members, sites: usage.sites } : undefined,
    remediation: remediation(pkg, advisory),
  };
}

function remediation(pkg: InstalledPackage, advisory: Advisory): Remediation {
  if (advisory.malicious) {
    return {
      type: 'MAJOR',
      description: `${pkg.name}@${pkg.version} is a known malicious package. Remove it and rotate any secrets exposed to the environment.`,
      action: pkg.direct ? `npm uninstall ${pkg.name}` : `Remove the dependency that pulls in ${pkg.name} (${pkg.via.join(', ')})`,
    };
  }
  const fixed = advisory.fixed_version;
  if (!fixed) {
    return {
      type: 'MAJOR',
      description: `No patched version of ${pkg.name} is published for this advisory. Consider replacing the package or mitigating the affected feature.`,
    };
  }
  const major = safeMajor(fixed) > safeMajor(pkg.version);
  if (pkg.direct) {
    return {
      type: major ? 'MAJOR' : 'MINOR',
      description: `Upgrade ${pkg.name} from ${pkg.version} to ${fixed} or later.`,
      required_version: `>=${fixed}`,
      breaking_changes: major,
      action: `npm install ${pkg.name}@^${fixed}`,
    };
  }
  return {
    type: major ? 'MAJOR' : 'MINOR',
    description:
      `${pkg.name}@${pkg.version} comes in through ${pkg.via.join(', ') || 'another dependency'}. ` +
      `Upgrade that dependency to a release that requires ${pkg.name}>=${fixed}, or force it with an override.`,
    required_version: `>=${fixed}`,
    breaking_changes: major,
    action: `npm pkg set overrides.${pkg.name}=^${fixed} && npm install`,
  };
}

function safeMajor(version: string): number {
  return semver.valid(version) ? semver.major(version) : 0;
}

function compareFindings(a: VulnerabilityFinding, b: VulnerabilityFinding): number {
  return (
    Number(b.is_reachable) - Number(a.is_reachable) ||
    Number(!!b.vulnerability.is_exploited_in_wild) - Number(!!a.vulnerability.is_exploited_in_wild) ||
    SEVERITY_ORDER[b.vulnerability.severity] - SEVERITY_ORDER[a.vulnerability.severity] ||
    (b.vulnerability.epss_score ?? 0) - (a.vulnerability.epss_score ?? 0) ||
    a.vulnerability.package.localeCompare(b.vulnerability.package)
  );
}

function riskScore(reachable: VulnerabilityFinding[]): number {
  if (reachable.length === 0) return 0;
  const base: Record<Severity, number> = { CRITICAL: 90, HIGH: 70, MEDIUM: 45, LOW: 20 };
  const worst = Math.max(
    ...reachable.map(f => {
      const kev = f.vulnerability.is_exploited_in_wild ? 10 : 0;
      const epss = Math.round(((f.vulnerability.epss_score ?? 0) / 100) * 10);
      return base[f.vulnerability.severity] + kev + epss;
    }),
  );
  return Math.min(100, worst);
}
