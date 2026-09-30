import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFile } from 'child_process';
import { parse as parseToml } from 'smol-toml';
import { CacheManager } from '../cache_manager.js';
import { flattenGraph, type DependencyInventory, type GraphNode, type InstalledPackage, type Root } from '../inventory_types.js';
import { MavenResolver, type MavenDep } from './maven_resolver.js';
import { ProjectFs } from '../project_fs.js';

export interface JavaInventoryOptions {
  /** Allow running mvn/gradle (executes the project's build logic). */
  allowBuildTool: boolean;
  includeDev: boolean;
  cache: CacheManager;
  onProgress?: (message: string) => void;
  /** Confines reads of build files to the scanned directory (defaults to the project directory). */
  pfs?: ProjectFs;
}

const BUILD_TIMEOUT = 15 * 60 * 1000;
const GRADLE_FILES = ['build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts'];
const SKIP_DIRS = new Set(['node_modules', '.git', 'target', 'build', 'out', '.gradle', '.idea', 'bin']);

export const hasMavenManifest = (dir: string) => fs.existsSync(path.join(dir, 'pom.xml'));
export const hasGradleManifest = (dir: string) => GRADLE_FILES.some(f => fs.existsSync(path.join(dir, f)));

function run(cmd: string, args: string[], cwd: string): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  return new Promise(resolve => {
    execFile(
      cmd,
      args,
      { cwd, timeout: BUILD_TIMEOUT, maxBuffer: 256 * 1024 * 1024, env: { ...process.env, TERM: 'dumb' } },
      (error, stdout, stderr) => resolve({ ok: !error, stdout: String(stdout), stderr: String(stderr || error?.message || '') }),
    );
  });
}

function onPath(cmd: string): boolean {
  return (process.env.PATH ?? '').split(path.delimiter).some(dir => {
    try {
      fs.accessSync(path.join(dir, cmd), fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

function findFiles(dir: string, name: string, maxDepth = 6): string[] {
  const out: string[] = [];
  const walk = (d: string, depth: number) => {
    if (depth > maxDepth) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isFile() && e.name === name) out.push(path.join(d, e.name));
      else if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(path.join(d, e.name), depth + 1);
    }
  };
  walk(dir, 0);
  return out;
}

const tail = (text: string) => text.trim().split('\n').slice(-3).join(' | ').slice(0, 300);

// ---------------------------------------------------------------- Maven

export async function readMavenInventory(dir: string, opts: JavaInventoryOptions): Promise<DependencyInventory> {
  const warnings: string[] = [];
  const mvnw = path.join(dir, 'mvnw');
  const mvn = fs.existsSync(mvnw) ? mvnw : onPath('mvn') ? 'mvn' : null;

  if (opts.allowBuildTool && mvn) {
    opts.onProgress?.(
      `☕ Running ${path.basename(mvn)} dependency:tree (executes this project's Maven build; use --no-build-tool for untrusted repos)...`,
    );
    const outFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-mvn-')), 'tree.txt');
    const res = await run(
      mvn,
      [
        '-B',
        '-q',
        'org.apache.maven.plugins:maven-dependency-plugin:3.6.1:tree',
        '-DoutputType=text',
        `-DoutputFile=${outFile}`,
        '-DappendOutput=true',
      ],
      dir,
    );
    if (res.ok && fs.existsSync(outFile)) {
      const packages = parseMavenTree(fs.readFileSync(outFile, 'utf-8'));
      return { ecosystem: 'Maven', source: 'mvn dependency:tree', lockfilePath: path.join(dir, 'pom.xml'), packages, warnings };
    }
    warnings.push(`mvn dependency:tree failed (${tail(res.stderr || res.stdout)}); falling back to reading pom.xml`);
  } else if (!mvn) {
    warnings.push('Maven not found: resolving dependencies from pom.xml and Maven Central (approximate). Install Maven for exact results.');
  } else {
    warnings.push('Build tools disabled: resolving dependencies from pom.xml and Maven Central (approximate).');
  }

  opts.onProgress?.('☕ Resolving Maven dependencies from pom.xml + Maven Central...');
  const resolver = new MavenResolver(opts.cache, opts.pfs ?? new ProjectFs(dir));
  const poms = findFiles(dir, 'pom.xml');
  const models = (await Promise.all(poms.map(p => resolver.localModel(p)))).filter(m => m !== null);
  const localModules = new Set(models.map(m => `${m!.groupId}:${m!.artifactId}`));
  const depMgmt = new Map<string, MavenDep>();
  const rootDeps: Array<MavenDep & { from: string }> = [];
  for (const model of models) {
    for (const [k, v] of model!.depMgmt) if (!depMgmt.has(k)) depMgmt.set(k, v);
  }
  for (const model of models) {
    for (const d of model!.deps) {
      const version = d.version ?? model!.depMgmt.get(`${d.groupId}:${d.artifactId}`)?.version;
      rootDeps.push({ ...d, version, from: model!.artifactId });
    }
  }
  const { nodes, roots } = await resolver.resolve(rootDeps, depMgmt, localModules);
  warnings.push(...resolver.warnings);
  return {
    ecosystem: 'Maven',
    source: 'pom.xml (resolved via Maven Central)',
    lockfilePath: path.join(dir, 'pom.xml'),
    packages: flattenGraph('Maven', nodes, roots),
    warnings,
  };
}

/** Parses `mvn dependency:tree -DoutputType=text` output (possibly several modules appended). */
export function parseMavenTree(text: string): InstalledPackage[] {
  const nodes = new Map<string, GraphNode>();
  const roots: Root[] = [];
  const modules = new Set<string>();
  const lines = text.split(/\r?\n/).filter(l => l.trim());

  for (const line of lines) {
    if (!/^[|+\\ ]/.test(line)) {
      const [g, a] = line.trim().split(':');
      modules.add(`${g}:${a}`);
    }
  }

  const prodIds = new Set<string>();
  const stack: Array<{ id: string | null; depth: number }> = [];
  let skipBelow = Infinity;
  for (const line of lines) {
    const match = line.match(/^([| +\\-]*?)([+\\]- )(.+)$/);
    if (!match) {
      stack.length = 0;
      skipBelow = Infinity;
      continue;
    }
    const depth = (match[1].length + match[2].length) / 3;
    const coords = match[3].replace(/\s*\(.*\)\s*$/, '').trim().split(':');
    if (depth > skipBelow) continue;
    skipBelow = Infinity;
    if (coords.length < 4) continue;
    const [g, a] = coords;
    const scope = coords.length >= 5 ? coords[coords.length - 1] : 'compile';
    const version = coords.length >= 5 ? coords[coords.length - 2] : coords[3];
    const ga = `${g}:${a}`;
    while (stack.length && stack[stack.length - 1].depth >= depth) stack.pop();
    if (modules.has(ga)) {
      skipBelow = depth;
      continue;
    }
    const id = `${ga}@${version}`;
    if (!nodes.has(id)) nodes.set(id, { name: ga, version, deps: [] });
    if (scope !== 'test') prodIds.add(id);
    const parent = stack[stack.length - 1];
    if (parent?.id) nodes.get(parent.id)!.deps.push(id);
    else roots.push({ name: ga, nodeId: id, dev: scope === 'test' });
    stack.push({ id, depth });
  }
  // The tree prints each artifact once, at its nearest position, with its effective scope. An artifact
  // shown under a test dependency can still be compile-scoped through a path the tree omits.
  const testRoots = new Set(roots.filter(r => r.dev).map(r => r.name));
  return flattenGraph('Maven', nodes, roots).map(pkg => {
    const prod = prodIds.has(`${pkg.name}@${pkg.version}`);
    if (!prod) return { ...pkg, dev: true };
    const onlyTestParents = pkg.via.length > 0 && pkg.via.every(v => testRoots.has(v));
    return { ...pkg, dev: false, via: onlyTestParents && !pkg.direct ? [] : pkg.via };
  });
}

// ---------------------------------------------------------------- Gradle

export async function readGradleInventory(dir: string, opts: JavaInventoryOptions): Promise<DependencyInventory> {
  const warnings: string[] = [];
  const pfs = opts.pfs ?? new ProjectFs(dir);
  const declared = parseGradleBuildFiles(dir, pfs);

  const legacyLocks = path.join(dir, 'gradle', 'dependency-locks');
  const lockfiles = [
    ...findFiles(dir, 'gradle.lockfile', 3),
    ...pfs.readdir(legacyLocks).filter(f => f.endsWith('.lockfile')).map(f => path.join(legacyLocks, f)),
  ].filter(f => pfs.inside(f));
  if (lockfiles.length) {
    const packages = parseGradleLockfiles(lockfiles, pfs, new Set(declared.deps.map(d => `${d.groupId}:${d.artifactId}`)));
    return { ecosystem: 'Maven', source: 'gradle.lockfile', lockfilePath: lockfiles[0], packages, warnings };
  }

  const gradlew = path.join(dir, 'gradlew');
  const gradle = fs.existsSync(gradlew) ? gradlew : onPath('gradle') ? 'gradle' : null;
  if (opts.allowBuildTool && gradle) {
    opts.onProgress?.(
      `🐘 Running ${path.basename(gradle)} dependencies (executes this project's Gradle build; use --no-build-tool for untrusted repos)...`,
    );
    const projects = [':', ...gradleSubprojects(dir, pfs).map(p => `:${p}:`)];
    const configs = opts.includeDev ? ['runtimeClasspath', 'testRuntimeClasspath'] : ['runtimeClasspath'];
    const all: InstalledPackage[] = [];
    let failed = '';
    for (const config of configs) {
      const args = ['-q', '--console=plain'];
      for (const p of projects) args.push(`${p === ':' ? '' : p}dependencies`, '--configuration', config);
      const res = await run(gradle, args, dir);
      if (!res.ok && !res.stdout.includes('--- ')) {
        failed = tail(res.stderr || res.stdout);
        break;
      }
      for (const pkg of parseGradleTree(res.stdout)) all.push({ ...pkg, dev: config !== 'runtimeClasspath' });
    }
    if (!failed) {
      return { ecosystem: 'Maven', source: 'gradle dependencies', lockfilePath: path.join(dir, 'build.gradle'), packages: mergeDev(all), warnings };
    }
    warnings.push(`gradle dependencies failed (${failed}); falling back to reading build files`);
  } else if (!gradle) {
    warnings.push('Gradle wrapper not found: resolving declared dependencies via Maven Central (approximate).');
  } else {
    warnings.push('Build tools disabled: resolving declared Gradle dependencies via Maven Central (approximate).');
  }

  opts.onProgress?.('🐘 Resolving Gradle dependencies from build files + Maven Central...');
  const resolver = new MavenResolver(opts.cache, pfs);
  const depMgmt = new Map<string, MavenDep>();
  for (const bom of declared.boms) {
    const [g, a, v] = bom.split(':');
    await resolver.importBom(depMgmt, g, a, v);
  }
  const { nodes, roots } = await resolver.resolve(
    declared.deps.map(d => ({ ...d, from: 'gradle' })),
    depMgmt,
    new Set(),
  );
  warnings.push(...resolver.warnings, ...declared.warnings);
  return {
    ecosystem: 'Maven',
    source: 'build.gradle (resolved via Maven Central)',
    lockfilePath: path.join(dir, fs.existsSync(path.join(dir, 'build.gradle.kts')) ? 'build.gradle.kts' : 'build.gradle'),
    packages: flattenGraph('Maven', nodes, roots),
    warnings,
  };
}

function mergeDev(pkgs: InstalledPackage[]): InstalledPackage[] {
  const out = new Map<string, InstalledPackage>();
  for (const p of pkgs) {
    const key = `${p.name}@${p.version}`;
    const existing = out.get(key);
    if (!existing) out.set(key, { ...p });
    else {
      existing.dev &&= p.dev;
      existing.direct ||= p.direct;
      existing.via = [...new Set([...existing.via, ...p.via])].sort();
    }
  }
  for (const p of out.values()) if (p.direct) p.via = [];
  return [...out.values()];
}

function gradleSubprojects(dir: string, pfs: ProjectFs): string[] {
  const settings = ['settings.gradle', 'settings.gradle.kts'].map(f => path.join(dir, f)).find(f => pfs.exists(f));
  if (!settings) return [];
  const text = pfs.read(settings).replace(/\/\/.*$/gm, '');
  const out: string[] = [];
  for (const m of text.matchAll(/\binclude\s*\(?([^)\n]+)\)?/g)) {
    for (const s of m[1].matchAll(/["']:?([^"']+)["']/g)) {
      const name = s[1].replace(/^:/, '');
      // Project paths become gradle arguments; reject anything that is not a plain project path.
      if (/^[A-Za-z0-9_][A-Za-z0-9_.:-]*$/.test(name)) out.push(name);
    }
  }
  return [...new Set(out)];
}

/** Parses `gradle dependencies --configuration X` output for one or more projects. */
export function parseGradleTree(text: string): InstalledPackage[] {
  const nodes = new Map<string, GraphNode>();
  const roots: Root[] = [];
  const stack: Array<{ id: string | null; depth: number }> = [];
  let skipBelow = Infinity;

  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([| ]*)[+\\]--- (.+)$/);
    if (!match) {
      if (line.trim() && !line.startsWith(' ')) {
        stack.length = 0;
        skipBelow = Infinity;
      }
      continue;
    }
    const depth = match[1].length / 5;
    if (depth > skipBelow) continue;
    skipBelow = Infinity;
    while (stack.length && stack[stack.length - 1].depth >= depth) stack.pop();
    let spec = match[2].trim();
    if (spec.startsWith('project ')) {
      skipBelow = depth;
      continue;
    }
    if (/\((c|n)\)$/.test(spec)) continue;
    spec = spec.replace(/\s*\(\*\)$/, '');
    const [coords, resolved] = spec.split(/\s*->\s*/);
    const parts = coords.split(':');
    if (parts.length < 2) continue;
    const version = (resolved ?? parts[2] ?? '').replace(/\s*\(.*\)$/, '').replace(/[{}]|strictly\s*/g, '').trim();
    if (!version) continue;
    const ga = `${parts[0]}:${parts[1]}`;
    const id = `${ga}@${version}`;
    if (!nodes.has(id)) nodes.set(id, { name: ga, version, deps: [] });
    const parent = stack[stack.length - 1];
    if (parent?.id) {
      if (!nodes.get(parent.id)!.deps.includes(id)) nodes.get(parent.id)!.deps.push(id);
    } else roots.push({ name: ga, nodeId: id, dev: false });
    stack.push({ id, depth });
  }
  return flattenGraph('Maven', nodes, roots);
}

function parseGradleLockfiles(files: string[], pfs: ProjectFs, declared: Set<string>): InstalledPackage[] {
  const out = new Map<string, InstalledPackage>();
  for (const file of files) {
    for (const line of pfs.read(file).split(/\r?\n/)) {
      const m = line.match(/^([^#:=\s]+):([^:=\s]+):([^=\s]+)=(.*)$/);
      if (!m) continue;
      const [, g, a, v, confs] = m;
      const dev = confs.split(',').every(c => /test/i.test(c));
      const name = `${g}:${a}`;
      const key = `${name}@${v}`;
      const existing = out.get(key);
      if (existing) existing.dev &&= dev;
      else {
        out.set(key, {
          ecosystem: 'Maven',
          name,
          version: v,
          direct: declared.size ? declared.has(name) : true,
          directKnown: declared.size > 0,
          dev,
          via: [],
        });
      }
    }
  }
  return [...out.values()];
}

interface DeclaredGradle {
  deps: MavenDep[];
  boms: string[];
  warnings: string[];
}

export function parseGradleBuildFiles(dir: string, pfs = new ProjectFs(dir)): DeclaredGradle {
  const files = [...findFiles(dir, 'build.gradle', 4), ...findFiles(dir, 'build.gradle.kts', 4)].filter(f => pfs.inside(f));
  const vars = gradleVariables(dir, files, pfs);
  const catalog = readVersionCatalog(dir, pfs);
  const deps: MavenDep[] = [];
  const boms = new Set<string>();
  const unresolved = new Set<string>();
  const sub = (s: string) => s.replace(/\$\{?([\w.]+)\}?/g, (w, k) => vars[k] ?? w);
  const CONFIG = /\b(implementation|api|compile|runtimeOnly|runtime|compileOnly|testImplementation|testRuntimeOnly|testCompile|testCompileOnly|kapt|annotationProcessor)\b/;

  for (const file of files) {
    const text = pfs.read(file).replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    const boot = text.match(/id\s*\(?\s*["']org\.springframework\.boot["']\s*\)?\s*version\s*\(?\s*["']([^"']+)["']/);
    if (boot) boms.add(`org.springframework.boot:spring-boot-dependencies:${sub(boot[1])}`);
    for (const m of text.matchAll(/(?:enforcedPlatform|platform|mavenBom)\s*\(?\s*["']([^"':]+):([^"':]+):([^"']+)["']/g)) {
      boms.add(`${m[1]}:${m[2]}:${sub(m[3])}`);
    }
    for (const line of text.split('\n')) {
      const config = line.match(CONFIG)?.[1];
      if (!config) continue;
      const dev = /^test/.test(config);
      const scope = dev ? 'test' : 'compile';
      if (/platform\s*\(/.test(line)) continue;
      const str = line.match(/["']([^"'$:\s]+|\$\{?[\w.]+\}?):([^"':\s]+):?([^"'@:\s]*)[^"']*["']/);
      if (str) {
        const version = sub(str[3] ?? '');
        deps.push({ groupId: sub(str[1]), artifactId: sub(str[2]), version: version && !version.includes('$') ? version : undefined, scope, exclusions: [] });
        continue;
      }
      const map = line.match(/group\s*[:=]\s*["']([^"']+)["']\s*,\s*name\s*[:=]\s*["']([^"']+)["'](?:\s*,\s*version\s*[:=]\s*["']([^"']+)["'])?/);
      if (map) {
        deps.push({ groupId: map[1], artifactId: map[2], version: map[3] ? sub(map[3]) : undefined, scope, exclusions: [] });
        continue;
      }
      const lib = line.match(/\blibs\.([\w.]+)/);
      if (lib) {
        const entry = catalog.libraries.get(lib[1].replace(/[._-]/g, '.').toLowerCase());
        if (entry) deps.push({ ...entry, scope, exclusions: [] });
        else if (!lib[1].startsWith('plugins') && !lib[1].startsWith('versions')) unresolved.add(`libs.${lib[1]}`);
      }
    }
  }
  const warnings = unresolved.size ? [`Could not resolve version catalog entries: ${[...unresolved].slice(0, 5).join(', ')}`] : [];
  return { deps, boms: [...boms], warnings };
}

function gradleVariables(dir: string, files: string[], pfs: ProjectFs): Record<string, string> {
  const vars: Record<string, string> = {};
  const propsFile = path.join(dir, 'gradle.properties');
  if (pfs.exists(propsFile)) {
    for (const line of pfs.read(propsFile).split(/\r?\n/)) {
      const m = line.match(/^\s*([\w.]+)\s*=\s*(.+?)\s*$/);
      if (m) vars[m[1]] = m[2];
    }
  }
  for (const file of files) {
    const text = pfs.read(file);
    for (const m of text.matchAll(/(?:val|var|def|set\s*\(|ext\.)?\s*["']?([A-Za-z_][\w.]*)["']?\s*(?:=|,)\s*["']([0-9][^"'$]*)["']/g)) {
      vars[m[1].replace(/^ext\./, '')] ??= m[2];
    }
  }
  return vars;
}

function readVersionCatalog(dir: string, pfs: ProjectFs): { libraries: Map<string, { groupId: string; artifactId: string; version?: string }> } {
  const libraries = new Map<string, { groupId: string; artifactId: string; version?: string }>();
  const file = path.join(dir, 'gradle', 'libs.versions.toml');
  if (!pfs.exists(file)) return { libraries };
  let toml: any;
  try {
    toml = parseToml(pfs.read(file));
  } catch {
    return { libraries };
  }
  const versions: Record<string, any> = toml.versions ?? {};
  const versionOf = (v: any): string | undefined => {
    if (typeof v === 'string') return v;
    if (v?.ref) return versionOf(versions[v.ref]);
    return v?.strictly ?? v?.require ?? v?.prefer;
  };
  for (const [alias, def] of Object.entries<any>(toml.libraries ?? {})) {
    let groupId: string | undefined;
    let artifactId: string | undefined;
    let version: string | undefined;
    if (typeof def === 'string') [groupId, artifactId, version] = def.split(':');
    else {
      [groupId, artifactId] = def.module ? def.module.split(':') : [def.group, def.name];
      version = versionOf(def.version);
    }
    if (groupId && artifactId) libraries.set(alias.replace(/[._-]/g, '.').toLowerCase(), { groupId, artifactId, version });
  }
  return { libraries };
}
