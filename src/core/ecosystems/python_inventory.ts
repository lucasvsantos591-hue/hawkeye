import * as fs from 'fs';
import * as path from 'path';
import { parse as parseToml } from 'smol-toml';
import { flattenGraph, type DependencyInventory, type GraphNode, type InstalledPackage, type Root } from '../inventory_types.js';
import { normalizePyName } from '../versions.js';
import { ProjectFs } from '../project_fs.js';

export const PYTHON_LOCKFILES = ['uv.lock', 'poetry.lock', 'pdm.lock', 'pylock.toml', 'Pipfile.lock'];
const DEV_GROUP = /^(dev|test|tests|testing|lint|docs?|typing|mypy|ci)$/i;
const DEV_REQ_FILE = /(^|[-_/])(dev|test|tests|testing|lint|docs?|ci)([-_.]|$)/i;

export function hasPythonManifest(dir: string): boolean {
  return (
    [...PYTHON_LOCKFILES, 'pyproject.toml', 'Pipfile', 'setup.py'].some(f => fs.existsSync(path.join(dir, f))) ||
    requirementFiles(dir).length > 0
  );
}

/** True when the directory pins its own versions (lockfile or requirements file). */
export function hasPythonLock(dir: string): boolean {
  return PYTHON_LOCKFILES.some(f => fs.existsSync(path.join(dir, f))) || requirementFiles(dir).length > 0;
}

export function readPythonInventory(dir: string, pfs = new ProjectFs(dir)): DependencyInventory {
  const warnings: string[] = [];
  const pyproject = readToml(path.join(dir, 'pyproject.toml'), pfs);
  const declared = declaredDeps(pyproject, readToml(path.join(dir, 'Pipfile'), pfs));

  for (const lock of PYTHON_LOCKFILES) {
    const file = path.join(dir, lock);
    if (!pfs.exists(file)) continue;
    const packages =
      lock === 'Pipfile.lock'
        ? pipfileLock(JSON.parse(pfs.read(file)), declared)
        : tomlLock(lock, readToml(file, pfs), declared, pyproject);
    return { ecosystem: 'PyPI', source: lock, lockfilePath: file, packages, warnings };
  }

  const reqFiles = requirementFiles(dir);
  if (reqFiles.length) {
    const packages = requirementsInventory(dir, reqFiles, declared, warnings, pfs);
    return {
      ecosystem: 'PyPI',
      source: reqFiles.map(f => path.relative(dir, f)).join(', '),
      lockfilePath: reqFiles[0],
      packages,
      warnings,
    };
  }

  if (declared.size === 0) return { ecosystem: 'PyPI', source: 'pyproject.toml', packages: [], warnings };
  warnings.push(
    'No Python lockfile or pinned requirements found: scanning declared dependencies at their minimum version. ' +
      'Commit uv.lock / poetry.lock / requirements.txt (pip freeze or pip-compile) for accurate results.',
  );
  const packages: InstalledPackage[] = [];
  for (const [name, info] of declared) {
    if (!info.minVersion) continue;
    packages.push({ ecosystem: 'PyPI', name, version: info.minVersion, direct: true, dev: info.dev, via: [] });
  }
  return { ecosystem: 'PyPI', source: 'pyproject.toml', packages, warnings };
}

interface Declared {
  dev: boolean;
  minVersion?: string;
}

function readToml(file: string, pfs: ProjectFs): any {
  if (!pfs.exists(file)) return undefined;
  try {
    return parseToml(pfs.read(file));
  } catch {
    return undefined;
  }
}

function parseRequirement(spec: string): { name: string; minVersion?: string } | null {
  const match = spec.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/);
  if (!match) return null;
  const constraint = match[3].split(';')[0];
  const pinned = constraint.match(/(?:===?|>=|~=|\^|~)\s*v?([0-9][^\s,;]*)/);
  return { name: normalizePyName(match[1]), minVersion: pinned?.[1] };
}

function declaredDeps(pyproject: any, pipfile: any): Map<string, Declared> {
  const out = new Map<string, Declared>();
  const add = (spec: string, dev: boolean) => {
    const req = parseRequirement(spec);
    if (req && req.name !== 'python' && !out.has(req.name)) out.set(req.name, { dev, minVersion: req.minVersion });
  };
  const addTable = (table: Record<string, any> | undefined, dev: boolean) => {
    for (const [name, value] of Object.entries(table ?? {})) {
      const version = typeof value === 'string' ? value : typeof value?.version === 'string' ? value.version : '';
      add(`${name} ${version === '*' ? '' : version}`, dev);
    }
  };

  for (const spec of pyproject?.project?.dependencies ?? []) add(spec, false);
  for (const [group, specs] of Object.entries<any>(pyproject?.project?.['optional-dependencies'] ?? {})) {
    for (const spec of specs) add(spec, DEV_GROUP.test(group));
  }
  for (const specs of Object.values<any>(pyproject?.['dependency-groups'] ?? {})) {
    for (const spec of specs) if (typeof spec === 'string') add(spec, true);
  }
  const poetry = pyproject?.tool?.poetry;
  addTable(poetry?.dependencies, false);
  addTable(poetry?.['dev-dependencies'], true);
  for (const [group, value] of Object.entries<any>(poetry?.group ?? {})) {
    addTable(value?.dependencies, group !== 'main');
  }
  for (const specs of Object.values<any>(pyproject?.tool?.pdm?.['dev-dependencies'] ?? {})) {
    for (const spec of specs) add(spec, true);
  }
  for (const spec of pyproject?.tool?.uv?.['dev-dependencies'] ?? []) add(spec, true);
  addTable(pipfile?.packages, false);
  addTable(pipfile?.['dev-packages'], true);
  return out;
}

/** uv.lock, poetry.lock, pdm.lock and pylock.toml (PEP 751) all list packages with name/version/dependencies. */
function tomlLock(kind: string, lock: any, declared: Map<string, Declared>, pyproject: any): InstalledPackage[] {
  const nodes = new Map<string, GraphNode>();
  const idsByName = new Map<string, string[]>();
  const pending: Array<[string, string[]]> = [];
  const rootEntries: any[] = [];
  const projectName = normalizePyName(pyproject?.project?.name ?? pyproject?.tool?.poetry?.name ?? '');

  for (const pkg of lock?.package ?? lock?.packages ?? []) {
    const name = normalizePyName(pkg.name ?? '');
    if (!name) continue;
    const source = pkg.source ?? {};
    if (kind === 'uv.lock' && (source.editable || source.virtual || (name === projectName && !pkg.sdist && !pkg.wheels))) {
      rootEntries.push(pkg);
      continue;
    }
    const id = `${name}@${pkg.version}`;
    nodes.set(id, { name, version: String(pkg.version), deps: [] });
    idsByName.set(name, [...(idsByName.get(name) ?? []), id]);
    pending.push([id, depNames(pkg)]);
  }
  for (const [id, deps] of pending) {
    nodes.get(id)!.deps = deps.flatMap(d => idsByName.get(d) ?? []);
  }

  const roots: Root[] = [];
  const addRoot = (name: string, dev: boolean) => {
    for (const nodeId of idsByName.get(name) ?? []) roots.push({ name, nodeId, dev });
  };
  if (rootEntries.length) {
    for (const entry of rootEntries) {
      for (const d of depNames(entry)) addRoot(d, false);
      for (const deps of Object.values<any>(entry['dev-dependencies'] ?? {})) {
        for (const d of deps) addRoot(normalizePyName(d.name), true);
      }
      for (const [group, deps] of Object.entries<any>(entry['optional-dependencies'] ?? {})) {
        for (const d of deps) addRoot(normalizePyName(d.name), DEV_GROUP.test(group));
      }
    }
  }
  for (const [name, info] of declared) addRoot(name, info.dev);

  if (roots.length === 0) {
    // No manifest to tell us what is direct: treat every locked package as a root of unknown kind.
    return [...nodes.values()].map(n => ({
      ecosystem: 'PyPI' as const,
      name: n.name,
      version: n.version,
      direct: true,
      directKnown: false,
      dev: false,
      via: [],
    }));
  }
  const flat = flattenGraph('PyPI', nodes, dedupeRoots(roots));
  // Locked packages the graph does not connect to a root (e.g. pylock.toml has no edges) are kept
  // as transitive dependencies with an unknown path rather than silently dropped.
  const seen = new Set(flat.map(p => `${p.name}@${p.version}`));
  for (const node of nodes.values()) {
    if (seen.has(`${node.name}@${node.version}`)) continue;
    flat.push({ ecosystem: 'PyPI', name: node.name, version: node.version, direct: false, dev: false, via: [] });
  }
  return flat;
}

function dedupeRoots(roots: Root[]): Root[] {
  const seen = new Map<string, Root>();
  for (const root of roots) {
    const existing = seen.get(root.nodeId);
    if (!existing) seen.set(root.nodeId, root);
    else if (!root.dev) existing.dev = false;
  }
  return [...seen.values()];
}

function depNames(pkg: any): string[] {
  const optional = Object.values<any>(pkg['optional-dependencies'] ?? {}).flat();
  const deps = Array.isArray(pkg.dependencies) ? [...pkg.dependencies, ...optional] : pkg.dependencies;
  if (Array.isArray(deps)) {
    return deps
      .map((d: any) => (typeof d === 'string' ? parseRequirement(d)?.name : d?.name && normalizePyName(d.name)))
      .filter((n: string | undefined): n is string => !!n);
  }
  return Object.keys(deps ?? {}).map(normalizePyName);
}

function pipfileLock(lock: any, declared: Map<string, Declared>): InstalledPackage[] {
  const out = new Map<string, InstalledPackage>();
  for (const [section, dev] of [['default', false], ['develop', true]] as const) {
    for (const [rawName, info] of Object.entries<any>(lock?.[section] ?? {})) {
      const version = String(info?.version ?? '').replace(/^==/, '');
      if (!version) continue;
      const name = normalizePyName(rawName);
      const key = `${name}@${version}`;
      const existing = out.get(key);
      if (existing) {
        existing.dev &&= dev;
        continue;
      }
      out.set(key, {
        ecosystem: 'PyPI',
        name,
        version,
        direct: declared.size ? declared.has(name) : true,
        directKnown: declared.size > 0,
        dev,
        via: [],
      });
    }
  }
  return [...out.values()];
}

function requirementFiles(dir: string): string[] {
  const candidates = new Set<string>();
  const consider = (base: string) => {
    let entries: string[] = [];
    try {
      entries = fs.readdirSync(base);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (/^(requirements|.*[-_]requirements|requirements[-_].*)\.txt$/i.test(entry)) candidates.add(path.join(base, entry));
    }
  };
  consider(dir);
  const reqDir = path.join(dir, 'requirements');
  if (fs.existsSync(reqDir) && fs.statSync(reqDir).isDirectory()) {
    for (const entry of fs.readdirSync(reqDir)) if (entry.endsWith('.txt')) candidates.add(path.join(reqDir, entry));
  }
  return [...candidates].sort((a, b) => Number(DEV_REQ_FILE.test(path.basename(a))) - Number(DEV_REQ_FILE.test(path.basename(b))));
}

interface ReqEntry {
  name: string;
  version: string;
  via: string[];
  directMarker: boolean;
  dev: boolean;
}

function requirementsInventory(
  dir: string,
  files: string[],
  declared: Map<string, Declared>,
  warnings: string[],
  pfs: ProjectFs,
): InstalledPackage[] {
  const entries: ReqEntry[] = [];
  const unpinned: string[] = [];
  const visited = new Set<string>();

  const readFile = (file: string, dev: boolean) => {
    const real = path.resolve(file);
    if (visited.has(real) || !fs.existsSync(real)) return;
    visited.add(real);
    if (!pfs.inside(real)) {
      warnings.push(`Ignored ${path.basename(real)}: it resolves outside the scanned directory`);
      return;
    }
    const lines = pfs.read(real).replace(/\\\r?\n/g, ' ').split(/\r?\n/);
    let current: ReqEntry | null = null;
    let inVia = false;
    for (const raw of lines) {
      const line = raw.trim();
      const via = line.match(/^#\s*via\s*(.*)$/);
      if (via && current) {
        inVia = true;
        addVia(current, via[1]);
        continue;
      }
      if (line.startsWith('#')) {
        if (inVia && current) addVia(current, line.replace(/^#\s*/, ''));
        continue;
      }
      inVia = false;
      const stripped = line.replace(/\s+#.*$/, '');
      if (!stripped) continue;
      const include = stripped.match(/^(?:-r|--requirement)\s*=?\s*(\S+)/);
      if (include) {
        readFile(path.join(path.dirname(real), include[1]), dev || DEV_REQ_FILE.test(include[1]));
        continue;
      }
      if (stripped.startsWith('-') || /^[a-z+]+:\/\//i.test(stripped) || stripped.includes(' @ ')) continue;
      const pin = stripped.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*===?\s*([^\s;,]+)/);
      if (!pin) {
        const name = parseRequirement(stripped)?.name;
        if (name) unpinned.push(name);
        current = null;
        continue;
      }
      current = { name: normalizePyName(pin[1]), version: pin[3], via: [], directMarker: false, dev };
      entries.push(current);
    }
  };

  const addVia = (entry: ReqEntry, text: string) => {
    for (const part of text.split(/,\s*/)) {
      const token = part.trim();
      if (!token) continue;
      if (token.startsWith('-r') || token.startsWith('-c') || token.endsWith('.in') || token.includes('pyproject.toml') || token.includes('setup.')) {
        entry.directMarker = true;
      } else if (/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(token)) {
        entry.via.push(normalizePyName(token));
      }
    }
  };

  for (const file of files) readFile(file, DEV_REQ_FILE.test(path.relative(dir, file)));
  if (unpinned.length) {
    warnings.push(`Skipped ${unpinned.length} unpinned requirement(s) (e.g. ${unpinned[0]}); pin versions with pip-compile or pip freeze.`);
  }

  const hasGraph = entries.some(e => e.via.length || e.directMarker);
  const inFiles = new Set(
    ['requirements.in', 'requirements-dev.in', 'dev-requirements.in']
      .map(f => path.join(dir, f))
      .filter(f => pfs.exists(f))
      .flatMap(f => pfs.read(f).split(/\r?\n/))
      .map(l => parseRequirement(l.replace(/#.*$/, ''))?.name)
      .filter((n): n is string => !!n),
  );

  if (hasGraph) {
    const nodes = new Map<string, GraphNode>();
    for (const e of entries) {
      if (!nodes.has(e.name)) nodes.set(e.name, { name: e.name, version: e.version, deps: [] });
    }
    for (const e of entries) {
      for (const parent of e.via) nodes.get(parent)?.deps.push(e.name);
    }
    const roots: Root[] = entries
      .filter(e => e.directMarker || e.via.length === 0 || inFiles.has(e.name) || declared.has(e.name))
      .map(e => ({ name: e.name, nodeId: e.name, dev: e.dev }));
    return flattenGraph('PyPI', nodes, dedupeRoots(roots));
  }

  const known = inFiles.size ? inFiles : new Set(declared.keys());
  const out = new Map<string, InstalledPackage>();
  for (const e of entries) {
    const key = `${e.name}@${e.version}`;
    if (out.has(key)) {
      out.get(key)!.dev &&= e.dev;
      continue;
    }
    out.set(key, {
      ecosystem: 'PyPI',
      name: e.name,
      version: e.version,
      direct: known.size ? known.has(e.name) : true,
      directKnown: known.size > 0,
      dev: e.dev,
      via: [],
    });
  }
  return [...out.values()];
}
