import * as path from 'path';
import { readNpmInventory } from './dependency_inventory.js';
import { readPythonInventory } from './ecosystems/python_inventory.js';
import { readGradleInventory, readMavenInventory } from './ecosystems/java_inventory.js';
import type { DependencyInventory, InstalledPackage } from './inventory_types.js';
import { discoverProjects, type DiscoveredProject, type ProjectKind } from './project_discovery.js';
import { buildImportIndex, type PackageUsage } from './import_index.js';
import { buildPythonIndex } from './python_index.js';
import { buildJavaIndex } from './java_index.js';
import { CacheManager, defaultCacheDir } from './cache_manager.js';
import { ProjectFs } from './project_fs.js';
import { allCveIds, applyThreatIntel, lookupThreatIntel, threatIntelInfo } from './threat_intel.js';
import { majorOf } from './versions.js';
import { OsvSource, packageKey, type Advisory } from '../adapters/vulnerability_sources/osv_source.js';
import type { AnalysisResult, Remediation, Severity, VulnerabilityFinding } from '../types/analysis-result.js';

export const TOOL_VERSION = '0.3.0';

/** An error caused by the analyzed input (safe to show to API callers), not by Hawkeye itself. */
export class AnalysisInputError extends Error {}

export interface AnalysisEngineOptions {
  projectPath: string;
  level?: 1 | 2 | 3;
  /** Kept for API compatibility; ecosystems are detected automatically. */
  language?: string;
  includeDev?: boolean;
  /** Restrict to some project kinds (default: all detected). */
  kinds?: ProjectKind[];
  /** Allow running mvn / gradle to resolve Java dependencies (default true). */
  allowBuildTool?: boolean;
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

interface ProjectScan {
  project: DiscoveredProject;
  inventory: DependencyInventory;
  packages: InstalledPackage[];
}

interface UsageProvider {
  filesScanned: number;
  usage(pkg: InstalledPackage): PackageUsage | undefined;
  runtimeLoaded?(pkg: InstalledPackage): string | null;
}

const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

export class AnalysisEngine {
  private readonly root: string;
  private readonly level: 1 | 2 | 3;
  private readonly includeDev: boolean;
  private readonly kinds?: ProjectKind[];
  private readonly allowBuildTool: boolean;
  private readonly cacheDir: string | null;
  private readonly progress: (message: string) => void;

  constructor(options: AnalysisEngineOptions) {
    this.root = path.resolve(options.projectPath);
    this.level = options.level ?? 2;
    this.includeDev = options.includeDev ?? false;
    this.kinds = options.kinds;
    this.allowBuildTool = options.allowBuildTool ?? true;
    this.cacheDir = options.cacheDir === undefined ? defaultCacheDir() : options.cacheDir;
    this.progress = options.onProgress ?? (() => {});
  }

  async analyze(): Promise<AnalysisResult> {
    const warnings: string[] = [];
    if (this.level === 3) {
      warnings.push('Level 3 (data-flow) is not implemented yet; results use level 2 (usage) analysis.');
    }

    const projects = discoverProjects(this.root, this.kinds);
    if (projects.length === 0) {
      throw new AnalysisInputError(
        'No supported project found (package.json, requirements*.txt / pyproject.toml / *.lock, pom.xml, build.gradle)',
      );
    }
    this.progress(`🗂️  Projects: ${projects.map(p => `${p.relDir} (${p.kind})`).join(', ')}`);

    const cache = new CacheManager(this.cacheDir);
    const pfs = new ProjectFs(this.root);
    const scans: ProjectScan[] = [];
    for (const project of projects) {
      try {
        const inventory = await this.readInventory(project, cache, pfs);
        warnings.push(...inventory.warnings.map(w => `${project.relDir} (${project.kind}): ${w}`));
        const packages = inventory.packages.filter(p => this.includeDev || !p.dev);
        this.progress(
          `📦 ${project.relDir}: ${packages.length} ${project.ecosystem} packages from ${inventory.source}` +
            (this.includeDev ? '' : ` (${inventory.packages.length - packages.length} dev-only skipped)`),
        );
        scans.push({ project, inventory, packages });
      } catch (error) {
        warnings.push(`${project.relDir} (${project.kind}): skipped, ${(error as Error).message}`);
      }
    }

    this.progress('🔎 Querying OSV.dev advisories...');
    const unique = new Map<string, InstalledPackage>();
    for (const scan of scans) for (const p of scan.packages) unique.set(packageKey(p), p);
    const advisories = await new OsvSource(cache).findAdvisories([...unique.values()]);

    const findings: VulnerabilityFinding[] = [];
    let filesScanned = 0;
    for (const scan of scans) {
      const vulnerable = scan.packages.filter(p => advisories.has(packageKey(p)));
      if (!vulnerable.length) continue;
      this.progress(`🧭 ${scan.project.relDir}: indexing ${scan.project.kind} source for ${vulnerable.length} vulnerable packages...`);
      const provider = this.usageProvider(scan.project, warnings);
      filesScanned += provider.filesScanned;
      const byName = new Map(scan.packages.map(p => [p.name, p]));
      for (const pkg of vulnerable) {
        const reach = this.reachability(pkg, provider, byName, scan.project.kind);
        for (const advisory of advisories.get(packageKey(pkg))!) {
          findings.push(buildFinding(pkg, advisory, reach, scan));
        }
      }
    }

    this.progress(`🌐 Enriching ${findings.length} findings with EPSS and CISA KEV...`);
    const intel = await lookupThreatIntel(allCveIds(findings.map(f => f.vulnerability)), cache);
    warnings.push(...intel.warnings);
    applyThreatIntel(findings, intel);
    cache.save();

    findings.sort(compareFindings);
    const reachable = findings.filter(f => f.is_reachable);
    const packagesScanned = scans.reduce((n, s) => n + s.packages.length, 0);

    return {
      schema_version: '1.3.0',
      generated_at: new Date().toISOString(),
      project_name: path.basename(this.root),
      ...(displayPath(this.root) !== undefined ? { project_path: displayPath(this.root) } : {}),
      total_vulnerabilities: findings.length,
      reachable_vulnerabilities: reachable.length,
      overall_risk_score: riskScore(reachable),
      summary: {
        critical_reachable: reachable.filter(f => f.vulnerability.severity === 'CRITICAL').length,
        high_reachable: reachable.filter(f => f.vulnerability.severity === 'HIGH').length,
        medium_reachable: reachable.filter(f => f.vulnerability.severity === 'MEDIUM').length,
        low_reachable: reachable.filter(f => f.vulnerability.severity === 'LOW').length,
        false_positives_filtered: findings.length - reachable.length,
      },
      results: findings,
      scan: {
        tool_version: TOOL_VERSION,
        vulnerability_source: 'OSV.dev (GitHub Advisory Database, PyPA, OSV)',
        dependency_source: scans.map(s => `${s.project.relDir}: ${s.inventory.source}`).join('; '),
        packages_scanned: packagesScanned,
        files_scanned: filesScanned,
        include_dev: this.includeDev,
        projects: scans.map(s => ({
          path: s.project.relDir,
          kind: s.project.kind,
          ecosystem: s.project.ecosystem,
          dependency_source: s.inventory.source,
          packages: s.packages.length,
        })),
        threat_intel: threatIntelInfo(intel),
        warnings,
      },
    };
  }

  private readInventory(project: DiscoveredProject, cache: CacheManager, pfs: ProjectFs): Promise<DependencyInventory> {
    const javaOpts = {
      allowBuildTool: this.allowBuildTool,
      includeDev: this.includeDev,
      cache,
      pfs,
      onProgress: this.progress,
    };
    switch (project.kind) {
      case 'npm':
        return Promise.resolve(readNpmInventory(project.dir, pfs));
      case 'python':
        return Promise.resolve(readPythonInventory(project.dir, pfs));
      case 'maven':
        return readMavenInventory(project.dir, javaOpts);
      case 'gradle':
        return readGradleInventory(project.dir, javaOpts);
    }
  }

  private usageProvider(project: DiscoveredProject, warnings: string[]): UsageProvider {
    if (project.kind === 'npm') {
      const index = buildImportIndex(project.dir);
      if (index.parseErrors.length) {
        warnings.push(`${project.relDir}: ${index.parseErrors.length} source files could not be parsed (e.g. ${index.parseErrors[0]})`);
      }
      return { filesScanned: index.filesScanned, usage: pkg => index.get(pkg.name) };
    }
    if (project.kind === 'python') {
      const index = buildPythonIndex(project.dir);
      warnings.push(...index.warnings.map(w => `${project.relDir}: ${w}`));
      return {
        filesScanned: index.filesScanned,
        usage: pkg => index.usage(pkg.name),
        runtimeLoaded: pkg => index.runtimeLoaded(pkg.name),
      };
    }
    const index = buildJavaIndex(project.dir);
    return { filesScanned: index.filesScanned, usage: pkg => index.usage(pkg.name, pkg.version) };
  }

  private reachability(
    pkg: InstalledPackage,
    provider: UsageProvider,
    byName: Map<string, InstalledPackage>,
    kind: ProjectKind,
  ): Reachability {
    if (pkg.direct) {
      const own = this.directReachability(pkg, provider, kind);
      if (own.isReachable || pkg.via.length === 0) return own;
      const [parent, ...others] = rankReachableParents(
        pkg,
        pkg.via.map(name => {
          const parentPkg = byName.get(name);
          return { name, reach: parentPkg ? this.directReachability(parentPkg, provider, kind) : null };
        }),
      );
      if (!parent) return own;
      return {
        ...parent.reach,
        usage: own.usage,
        confidence: Math.min(parent.reach.confidence, 60),
        via: parent.name,
        reason:
          `Not used directly, but ${parent.name} depends on it and is reachable (${parent.reach.reason.replace(/\.$/, '')}).` +
          alsoVia(others),
      };
    }

    if (pkg.via.length === 0) {
      const own = this.directReachability(pkg, provider, kind);
      if (own.isReachable) return own;
      return {
        isReachable: true,
        level: 1,
        confidence: 30,
        reason: 'Transitive dependency; could not resolve which direct dependency pulls it in, so it is treated as reachable.',
      };
    }
    const viaResults = pkg.via.map(name => {
      const parent = byName.get(name);
      return { name, reach: parent ? this.directReachability(parent, provider, kind) : null };
    });
    const [hit, ...others] = rankReachableParents(pkg, viaResults);
    if (hit) {
      return {
        ...hit.reach,
        confidence: Math.min(hit.reach.confidence, 60),
        via: hit.name,
        reason:
          `Transitive dependency of ${hit.name}, which is reachable (${hit.reach.reason.replace(/\.$/, '')}).` +
          alsoVia(others) +
          ' Whether the vulnerable code path inside it is exercised is not verified.',
      };
    }
    if (viaResults.some(v => v.reach === null)) {
      return {
        isReachable: true,
        level: 1,
        confidence: 30,
        reason: `Transitive dependency via ${pkg.via.join(', ')}; could not evaluate every parent, so it is treated as reachable.`,
      };
    }
    return {
      isReachable: false,
      level: 1,
      confidence: 60,
      reason: `Transitive dependency pulled in only by ${pkg.via.join(', ')}, none of which is used by project source.`,
    };
  }

  private directReachability(pkg: InstalledPackage, provider: UsageProvider, kind: ProjectKind): Reachability {
    const usage = provider.usage(pkg);
    const java = kind === 'maven' || kind === 'gradle';

    if (java) {
      if (pkg.dev) {
        return { isReachable: false, level: 1, confidence: 90, usage, reason: 'Test-scope dependency; not on the production classpath.' };
      }
      if (usage?.used) {
        return {
          isReachable: true,
          level: 2,
          confidence: 80,
          usage,
          reason: `Imported in ${usage.files.length} file(s). Classes: ${usage.members.slice(0, 6).join(', ')}.`,
        };
      }
      return {
        isReachable: true,
        level: 1,
        confidence: 40,
        usage,
        reason:
          'No direct imports found, but Java libraries are often loaded at runtime (logging backends, JDBC drivers, ' +
          'framework auto-configuration), so it is treated as reachable.',
      };
    }

    if (!usage || (usage.files.length === 0 && usage.testFiles.length === 0)) {
      const runtime = provider.runtimeLoaded?.(pkg);
      if (runtime) return { isReachable: true, level: 1, confidence: 50, reason: `${runtime}.` };
      if (pkg.directKnown === false) {
        return {
          isReachable: true,
          level: 1,
          confidence: 30,
          reason:
            'Not imported directly, and the dependency file does not say whether it is a transitive dependency ' +
            'of another package (e.g. pip freeze output), so it is treated as reachable.',
        };
      }
      return {
        isReachable: false,
        level: 1,
        confidence: kind === 'python' ? 60 : 70,
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
        reason:
          kind === 'python'
            ? 'Only imported under `if TYPE_CHECKING:`, which does not run at runtime.'
            : 'Only type imports, which are erased at compile time.',
      };
    }
    if (this.level === 1) {
      return { isReachable: true, level: 1, confidence: 60, usage, reason: `Imported in ${usage.files.length} file(s).` };
    }
    if (!usage.used) {
      return { isReachable: false, level: 2, confidence: 70, usage, reason: 'Imported, but the imported names are never used.' };
    }
    const members = usage.members.length ? ` Uses: ${usage.members.slice(0, 8).join(', ')}.` : '';
    return { isReachable: true, level: 2, confidence: 80, usage, reason: `Used in ${usage.files.length} file(s).${members}` };
  }
}

/**
 * The scanned path as it may appear in a report: relative to the working directory, or nothing when the
 * scan ran outside it (an absolute path exposes the user name and local folder layout of whoever ran it).
 */
function displayPath(root: string): string | undefined {
  const rel = path.relative(process.cwd(), root);
  if (rel === '') return '.';
  if (rel.startsWith('..') || path.isAbsolute(rel)) return undefined;
  return rel.split(path.sep).join('/');
}

/**
 * Reachable parents, strongest first: higher confidence, then deeper reachability, then the parent closest
 * to the package in the dependency graph (fastapi → starlette beats a library that reaches starlette only
 * through fastapi), then the one used in more files. The order of `via` is alphabetical and must not decide
 * which parent explains a finding.
 */
function rankReachableParents(
  pkg: InstalledPackage,
  parents: Array<{ name: string; reach: Reachability | null }>,
): Array<{ name: string; reach: Reachability }> {
  const depth = (name: string) => pkg.viaDepth?.[name] ?? Infinity;
  return parents
    .filter((p): p is { name: string; reach: Reachability } => !!p.reach?.isReachable)
    .sort(
      (a, b) =>
        b.reach.confidence - a.reach.confidence ||
        b.reach.level - a.reach.level ||
        (depth(a.name) === depth(b.name) ? 0 : depth(a.name) < depth(b.name) ? -1 : 1) ||
        (b.reach.usage?.files.length ?? 0) - (a.reach.usage?.files.length ?? 0) ||
        a.name.localeCompare(b.name),
    );
}

function alsoVia(others: Array<{ name: string }>): string {
  return others.length ? ` Also pulled in by ${others.map(o => o.name).join(', ')}, which ${others.length === 1 ? 'is' : 'are'} reachable too.` : '';
}

function buildFinding(
  pkg: InstalledPackage,
  advisory: Advisory,
  reach: Reachability,
  scan: ProjectScan,
): VulnerabilityFinding {
  const usage = reach.usage;
  const prefix = scan.project.relDir === '.' ? '' : `${scan.project.relDir}/`;
  const sites = usage?.sites.map(s => prefix + s) ?? [];
  return {
    vulnerability: {
      cve_id: advisory.cve_id,
      advisory_id: advisory.id,
      aliases: advisory.aliases,
      summary: advisory.summary,
      advisory_url: advisory.url,
      ecosystem: pkg.ecosystem,
      project: scan.project.relDir,
      manifest: manifestPath(scan),
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
      reach.isReachable && sites.length
        ? { entry_point: sites[0], path: reach.via ? [reach.via, pkg.name] : [pkg.name] }
        : undefined,
    reason: reach.reason,
    evidence: usage
      ? { files: usage.files.slice(0, 20).map(f => prefix + f), members: usage.members, sites }
      : undefined,
    remediation: remediation(pkg, advisory, scan),
  };
}

function manifestPath(scan: ProjectScan): string {
  const file = scan.inventory.lockfilePath ?? path.join(scan.project.dir, 'package.json');
  return path.join(scan.project.relDir, path.relative(scan.project.dir, file)).split(path.sep).join('/');
}

function remediation(pkg: InstalledPackage, advisory: Advisory, scan: ProjectScan): Remediation {
  if (advisory.malicious) {
    return {
      type: 'MAJOR',
      description: `${pkg.name}@${pkg.version} is a known malicious package. Remove it and rotate any secrets exposed to the environment.`,
      action: pkg.direct ? removeCommand(pkg, scan) : `Remove the dependency that pulls in ${pkg.name} (${pkg.via.join(', ')})`,
    };
  }
  const fixed = advisory.fixed_version;
  if (!fixed) {
    return {
      type: 'MAJOR',
      description: `No patched version of ${pkg.name} is published for this advisory. Consider replacing the package or mitigating the affected feature.`,
    };
  }
  const major = majorOf(fixed) > majorOf(pkg.version);
  const base = {
    type: (major ? 'MAJOR' : 'MINOR') as Remediation['type'],
    required_version: `>=${fixed}`,
    breaking_changes: major,
  };
  if (pkg.direct) {
    return {
      ...base,
      description: `Upgrade ${pkg.name} from ${pkg.version} to ${fixed} or later.`,
      action: upgradeCommand(pkg, fixed, scan),
    };
  }
  return {
    ...base,
    description:
      `${pkg.name}@${pkg.version} comes in through ${pkg.via.join(', ') || 'another dependency'}. ` +
      `Upgrade that dependency to a release that requires ${pkg.name}>=${fixed}, or pin it directly.`,
    action: pinTransitiveCommand(pkg, fixed, scan),
  };
}

function upgradeCommand(pkg: InstalledPackage, fixed: string, scan: ProjectScan): string {
  const source = scan.inventory.source;
  switch (scan.project.kind) {
    case 'npm':
      return `npm install ${pkg.name}@^${fixed}`;
    case 'python':
      if (source === 'poetry.lock') return `poetry add "${pkg.name}>=${fixed}"`;
      if (source === 'uv.lock') return `uv add "${pkg.name}>=${fixed}"`;
      if (source === 'pdm.lock') return `pdm add "${pkg.name}>=${fixed}"`;
      if (source === 'Pipfile.lock') return `pipenv install "${pkg.name}>=${fixed}"`;
      return `Set ${pkg.name}==${fixed} (or newer) in ${source.split(',')[0]} and reinstall`;
    case 'maven':
      return `mvn versions:use-dep-version -Dincludes=${pkg.name} -DdepVersion=${fixed} -DforceVersion=true`;
    case 'gradle':
      return `Change the version of "${pkg.name}" to ${fixed} in your Gradle build (or version catalog)`;
  }
}

function pinTransitiveCommand(pkg: InstalledPackage, fixed: string, scan: ProjectScan): string {
  switch (scan.project.kind) {
    case 'npm':
      return `npm pkg set overrides.${pkg.name}=^${fixed} && npm install`;
    case 'python':
      if (scan.inventory.source === 'uv.lock') return `Add "${pkg.name}>=${fixed}" to [tool.uv] constraint-dependencies, then uv lock`;
      if (scan.inventory.source === 'poetry.lock') return `poetry add "${pkg.name}>=${fixed}"`;
      return `Add ${pkg.name}>=${fixed} to a constraints file (pip install -c constraints.txt) or pin it in your requirements`;
    case 'maven':
      return `Pin ${pkg.name}:${fixed} in <dependencyManagement> of your pom.xml`;
    case 'gradle':
      return `dependencies { constraints { implementation("${pkg.name}:${fixed}") } }`;
  }
}

function removeCommand(pkg: InstalledPackage, scan: ProjectScan): string {
  switch (scan.project.kind) {
    case 'npm':
      return `npm uninstall ${pkg.name}`;
    case 'python':
      return `Remove ${pkg.name} from ${scan.inventory.source} and your manifest`;
    default:
      return `Remove ${pkg.name} from your build file`;
  }
}

function compareFindings(a: VulnerabilityFinding, b: VulnerabilityFinding): number {
  return (
    Number(b.is_reachable) - Number(a.is_reachable) ||
    Number(!!b.vulnerability.is_exploited_in_wild) - Number(!!a.vulnerability.is_exploited_in_wild) ||
    SEVERITY_ORDER[b.vulnerability.severity] - SEVERITY_ORDER[a.vulnerability.severity] ||
    b.confidence - a.confidence ||
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
