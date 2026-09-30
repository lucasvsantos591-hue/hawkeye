import * as fs from 'fs';
import * as path from 'path';
import semver from 'semver';
import * as yaml from 'js-yaml';
import { flattenGraph, type DependencyInventory, type GraphNode, type InstalledPackage, type Root } from './inventory_types.js';

export type { InstalledPackage, DependencyInventory } from './inventory_types.js';

type InventorySource = 'package-lock.json' | 'yarn.lock' | 'pnpm-lock.yaml' | 'bun.lock' | 'package.json';

interface Graph {
  nodes: Map<string, GraphNode>;
  roots: Root[];
}

export const NPM_LOCKFILES: InventorySource[] = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock'];

export function readNpmInventory(projectPath: string): DependencyInventory {
  const pkgJsonPath = path.join(projectPath, 'package.json');
  if (!fs.existsSync(pkgJsonPath)) {
    throw new Error(`package.json not found in ${projectPath}`);
  }
  const rootPkg = readJson(pkgJsonPath);
  const warnings: string[] = [];

  for (const lockName of NPM_LOCKFILES) {
    const lockfilePath = path.join(projectPath, lockName);
    if (!fs.existsSync(lockfilePath)) continue;

    const content = fs.readFileSync(lockfilePath, 'utf-8');
    let graph: Graph;
    if (lockName === 'package-lock.json') {
      graph = npmGraph(JSON.parse(content), rootPkg);
    } else if (lockName === 'pnpm-lock.yaml') {
      graph = pnpmGraph(yaml.load(content) as any);
    } else if (lockName === 'bun.lock') {
      graph = bunGraph(JSON.parse(content.replace(/,(\s*[}\]])/g, '$1')));
    } else {
      graph = yarnGraph(content, projectPath, rootPkg, warnings);
    }

    if (graph.roots.length === 0 && hasDeclaredDeps(rootPkg)) {
      warnings.push(`${lockName} does not match package.json; falling back to package.json ranges`);
      break;
    }
    return {
      ecosystem: 'npm',
      source: lockName,
      lockfilePath,
      packages: flattenGraph('npm', graph.nodes, graph.roots, v => !!semver.valid(v)),
      warnings,
    };
  }

  warnings.push(
    'No usable lockfile found: scanning direct dependencies only, at the lowest version allowed by package.json. ' +
      'Commit a lockfile for accurate results.',
  );
  return { ecosystem: 'npm', source: 'package.json', packages: manifestOnly(rootPkg, warnings), warnings };
}

function readJson(file: string): any {
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

function hasDeclaredDeps(pkg: any): boolean {
  return Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).length > 0;
}

function manifestOnly(pkg: any, warnings: string[]): InstalledPackage[] {
  const out: InstalledPackage[] = [];
  const add = (deps: Record<string, string> | undefined, dev: boolean) => {
    for (const [name, range] of Object.entries(deps ?? {})) {
      const min = semver.validRange(range) ? semver.minVersion(range) : null;
      if (!min) {
        warnings.push(`Skipping ${name}@${range}: not a semver range`);
        continue;
      }
      out.push({ ecosystem: 'npm', name, version: min.version, direct: true, dev, via: [] });
    }
  };
  add(pkg.dependencies, false);
  add(pkg.optionalDependencies, false);
  add(pkg.devDependencies, true);
  return out;
}

// ---------- npm (package-lock.json v1, v2, v3) ----------

function npmGraph(lock: any, rootPkg: any): Graph {
  const packages: Record<string, any> = lock.packages ?? npmV1ToPackages(lock, rootPkg);
  const nodes = new Map<string, GraphNode>();
  const roots: Root[] = [];

  const resolve = (fromKey: string, dep: string): string | null => {
    const parts = fromKey ? fromKey.split('/') : [];
    for (;;) {
      const base = parts.join('/');
      const candidate = (base ? `${base}/` : '') + `node_modules/${dep}`;
      const entry = packages[candidate];
      if (entry) return entry.link ? null : candidate;
      if (parts.length === 0) return null;
      parts.pop();
    }
  };

  for (const [key, entry] of Object.entries(packages)) {
    const isInstalled = key.includes('node_modules/');
    if (isInstalled) {
      if (entry.link) continue;
      const name = entry.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      const depNames = Object.keys({
        ...entry.dependencies,
        ...entry.optionalDependencies,
        ...entry.peerDependencies,
      });
      nodes.set(key, {
        name,
        version: entry.version,
        deps: depNames.map(d => resolve(key, d)).filter((d): d is string => d !== null),
      });
      continue;
    }
    // Root project ("") or a workspace member: its declared deps are direct deps.
    const addRoots = (deps: Record<string, string> | undefined, dev: boolean) => {
      for (const dep of Object.keys(deps ?? {})) {
        const nodeId = resolve(key, dep);
        if (nodeId) roots.push({ name: dep, nodeId, dev });
      }
    };
    addRoots(entry.dependencies, false);
    addRoots(entry.optionalDependencies, false);
    addRoots(entry.peerDependencies, false);
    addRoots(entry.devDependencies, true);
  }
  return { nodes, roots };
}

function npmV1ToPackages(lock: any, rootPkg: any): Record<string, any> {
  const packages: Record<string, any> = {
    '': {
      dependencies: rootPkg.dependencies,
      optionalDependencies: rootPkg.optionalDependencies,
      devDependencies: rootPkg.devDependencies,
    },
  };
  const walk = (deps: Record<string, any> | undefined, prefix: string) => {
    for (const [name, entry] of Object.entries(deps ?? {})) {
      const key = `${prefix}node_modules/${name}`;
      packages[key] = { version: entry.version, dependencies: entry.requires };
      walk(entry.dependencies, `${key}/`);
    }
  };
  walk(lock.dependencies, '');
  return packages;
}

// ---------- pnpm (pnpm-lock.yaml v5, v6, v9) ----------

function pnpmGraph(lock: any): Graph {
  const nodes = new Map<string, GraphNode>();
  const roots: Root[] = [];
  const major = parseFloat(String(lock?.lockfileVersion ?? '0'));
  const slashFormat = major < 6;

  const parseKey = (rawKey: string): { name: string; version: string } | null => {
    const key = rawKey.replace(/^\//, '').split('(')[0];
    const sep = slashFormat ? key.lastIndexOf('/') : key.lastIndexOf('@');
    if (sep <= 0) return null;
    const name = key.slice(0, sep);
    const version = key.slice(sep + 1).split('_')[0];
    return { name, version };
  };

  const refToId = (dep: string, ref: unknown): string | null => {
    const value = typeof ref === 'object' && ref !== null ? (ref as any).version : ref;
    if (typeof value !== 'string' || value.startsWith('link:') || value.startsWith('file:')) return null;
    if (value.startsWith('/') || /^[^\d].*@\d/.test(value)) {
      const parsed = parseKey(value);
      return parsed ? `${parsed.name}@${parsed.version}` : null;
    }
    return `${dep}@${value.split('(')[0].split('_')[0]}`;
  };

  const depsOf = (entry: any): string[] => {
    const all = { ...entry?.dependencies, ...entry?.optionalDependencies };
    return Object.entries(all)
      .map(([dep, ref]) => refToId(dep, ref))
      .filter((id): id is string => id !== null);
  };

  const graphSource = lock?.snapshots ?? lock?.packages ?? {};
  for (const rawKey of Object.keys(graphSource)) {
    const parsed = parseKey(rawKey);
    if (!parsed) continue;
    const id = `${parsed.name}@${parsed.version}`;
    const existing = nodes.get(id);
    const deps = depsOf(graphSource[rawKey]);
    if (existing) existing.deps.push(...deps);
    else nodes.set(id, { name: parsed.name, version: parsed.version, deps });
  }

  const importers: Record<string, any> = lock?.importers ?? { '.': lock ?? {} };
  for (const importer of Object.values(importers)) {
    const addRoots = (deps: Record<string, unknown> | undefined, dev: boolean) => {
      for (const [dep, ref] of Object.entries(deps ?? {})) {
        const nodeId = refToId(dep, ref);
        if (nodeId) roots.push({ name: dep, nodeId, dev });
      }
    };
    addRoots(importer.dependencies, false);
    addRoots(importer.optionalDependencies, false);
    addRoots(importer.devDependencies, true);
  }
  return { nodes, roots };
}

// ---------- bun (bun.lock, text format) ----------

function bunGraph(lock: any): Graph {
  const packages: Record<string, any[]> = lock?.packages ?? {};
  const nodes = new Map<string, GraphNode>();
  const roots: Root[] = [];

  const names = (key: string): string[] => {
    const parts = key.split('/');
    const out: string[] = [];
    for (let i = 0; i < parts.length; i++) {
      out.push(parts[i].startsWith('@') && i + 1 < parts.length ? `${parts[i]}/${parts[++i]}` : parts[i]);
    }
    return out;
  };
  const resolve = (fromKey: string, dep: string): string | null => {
    const chain = fromKey ? names(fromKey) : [];
    for (let i = chain.length; i >= 0; i--) {
      const key = [...chain.slice(0, i), dep].join('/');
      if (packages[key]) return nodes.has(key) || isInstalled(packages[key]) ? key : null;
    }
    return null;
  };
  const isInstalled = (entry: any[]) => typeof entry?.[0] === 'string' && !/@(workspace|link|file):/.test(entry[0]);

  for (const [key, entry] of Object.entries(packages)) {
    if (!isInstalled(entry)) continue;
    const spec = entry[0] as string;
    const at = spec.lastIndexOf('@');
    nodes.set(key, { name: spec.slice(0, at), version: spec.slice(at + 1), deps: [] });
  }
  for (const [key, entry] of Object.entries(packages)) {
    const node = nodes.get(key);
    const meta = entry.find((x: unknown) => typeof x === 'object' && x !== null && !Array.isArray(x)) ?? {};
    if (!node) continue;
    for (const dep of Object.keys({ ...meta.dependencies, ...meta.optionalDependencies, ...meta.peerDependencies })) {
      const target = resolve(key, dep);
      if (target) node.deps.push(target);
    }
  }
  for (const [wsPath, ws] of Object.entries<any>(lock?.workspaces ?? {})) {
    const from = wsPath === '' ? '' : ws.name ?? '';
    const addRoots = (deps: Record<string, string> | undefined, dev: boolean) => {
      for (const dep of Object.keys(deps ?? {})) {
        const nodeId = resolve(from, dep) ?? resolve('', dep);
        if (nodeId) roots.push({ name: dep, nodeId, dev });
      }
    };
    addRoots(ws.dependencies, false);
    addRoots(ws.optionalDependencies, false);
    addRoots(ws.peerDependencies, false);
    addRoots(ws.devDependencies, true);
  }
  return { nodes, roots };
}

// ---------- yarn (classic v1 and berry v2+) ----------

function yarnGraph(content: string, projectPath: string, rootPkg: any, warnings: string[]): Graph {
  const nodes = new Map<string, GraphNode>();
  const specToId = new Map<string, string>();
  const nameToIds = new Map<string, string[]>();
  const pendingDeps = new Map<string, Array<[string, string]>>();

  const normalizeRange = (range: string) => range.replace(/^"|"$/g, '').replace(/^npm:/, '');
  const splitSpec = (spec: string): [string, string] | null => {
    const at = spec.indexOf('@', 1);
    return at > 0 ? [spec.slice(0, at), normalizeRange(spec.slice(at + 1))] : null;
  };

  let current: { id: string; specs: Array<[string, string]>; name: string } | null = null;
  let inDeps = false;
  let skipBlock = false;

  for (const line of content.split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;
    const indent = line.length - line.trimStart().length;

    if (indent === 0) {
      inDeps = false;
      current = null;
      const header = line.replace(/:$/, '');
      const specs = header
        .split(/,\s*/)
        .map(s => s.replace(/^"|"$/g, ''))
        .map(splitSpec)
        .filter((s): s is [string, string] => s !== null);
      skipBlock =
        specs.length === 0 || specs.some(([, r]) => /^(workspace:|patch:|link:|portal:|file:)/.test(r));
      if (!skipBlock) current = { id: '', specs, name: specs[0][0] };
      continue;
    }
    if (skipBlock || !current) continue;

    const trimmed = line.trim();
    if (indent === 2) {
      inDeps = trimmed === 'dependencies:' || trimmed === 'optionalDependencies:';
      const versionMatch = trimmed.match(/^version:?\s+"?([^"\s]+)"?$/);
      if (versionMatch) {
        const id = `${current.name}@${versionMatch[1]}`;
        current.id = id;
        if (!nodes.has(id)) nodes.set(id, { name: current.name, version: versionMatch[1], deps: [] });
        if (!nameToIds.has(current.name)) nameToIds.set(current.name, []);
        nameToIds.get(current.name)!.push(id);
        for (const [name, range] of current.specs) specToId.set(`${name}@${range}`, id);
      }
      continue;
    }
    if (indent >= 4 && inDeps && current.id) {
      const depMatch = trimmed.match(/^"?([^"\s:]+(?:\/[^"\s:]+)?)"?:?\s+"?([^"]+?)"?$/);
      if (depMatch) {
        if (!pendingDeps.has(current.id)) pendingDeps.set(current.id, []);
        pendingDeps.get(current.id)!.push([depMatch[1], normalizeRange(depMatch[2])]);
      }
    }
  }

  const lookup = (name: string, range: string): string | null =>
    specToId.get(`${name}@${normalizeRange(range)}`) ?? nameToIds.get(name)?.[0] ?? null;

  for (const [id, deps] of pendingDeps) {
    const node = nodes.get(id)!;
    for (const [name, range] of deps) {
      const target = lookup(name, range);
      if (target) node.deps.push(target);
    }
  }

  const roots: Root[] = [];
  for (const manifest of [rootPkg, ...readWorkspaceManifests(projectPath, rootPkg, warnings)]) {
    const addRoots = (deps: Record<string, string> | undefined, dev: boolean) => {
      for (const [name, range] of Object.entries(deps ?? {})) {
        if (/^(workspace:|link:|file:)/.test(range)) continue;
        const nodeId = lookup(name, range);
        if (nodeId) roots.push({ name, nodeId, dev });
      }
    };
    addRoots(manifest.dependencies, false);
    addRoots(manifest.optionalDependencies, false);
    addRoots(manifest.devDependencies, true);
  }
  return { nodes, roots };
}

function readWorkspaceManifests(projectPath: string, rootPkg: any, warnings: string[]): any[] {
  const patterns: string[] = Array.isArray(rootPkg.workspaces)
    ? rootPkg.workspaces
    : rootPkg.workspaces?.packages ?? [];
  const manifests: any[] = [];
  for (const pattern of patterns) {
    const clean = pattern.replace(/\/\*\*?$/, '');
    const isGlob = clean !== pattern;
    if (clean.includes('*')) {
      warnings.push(`Workspace pattern "${pattern}" not supported; its dependencies are treated as transitive`);
      continue;
    }
    const dirs = isGlob
      ? safeReaddir(path.join(projectPath, clean)).map(d => path.join(projectPath, clean, d))
      : [path.join(projectPath, clean)];
    for (const dir of dirs) {
      const file = path.join(dir, 'package.json');
      if (fs.existsSync(file)) manifests.push(readJson(file));
    }
  }
  return manifests;
}

function safeReaddir(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}
