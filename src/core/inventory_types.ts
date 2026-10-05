import type { Ecosystem } from './versions.js';

export interface InstalledPackage {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
  /** Direct dependencies that pull this package in (for a direct dep: other direct deps that also need it). */
  via: string[];
  /** Edges from each `via` parent to this package (1 = the parent depends on it directly). */
  viaDepth?: Record<string, number>;
  /** False when the source (e.g. pip freeze output) cannot tell direct from transitive. */
  directKnown?: boolean;
  /** Maven scope or Gradle configuration, when known. */
  scope?: string;
}

export interface DependencyInventory {
  ecosystem: Ecosystem;
  source: string;
  lockfilePath?: string;
  packages: InstalledPackage[];
  warnings: string[];
}

export interface GraphNode {
  name: string;
  version: string;
  deps: string[];
}

export interface Root {
  name: string;
  nodeId: string;
  dev: boolean;
}

/**
 * Turns a dependency graph into a flat package list: which packages are direct, which are
 * only reachable from dev roots, and which direct dependencies pull each one in.
 */
export function flattenGraph(
  ecosystem: Ecosystem,
  nodes: Map<string, GraphNode>,
  roots: Root[],
  isValidVersion: (v: string) => boolean = v => !!v,
): InstalledPackage[] {
  // Direct dependencies that pull each node in, split by kind: a production package lists only its
  // production parents, so a test-only root (e.g. a mocking library) is never shown as its source.
  const viaByNode = new Map<string, { prod: Set<string>; dev: Set<string> }>();
  const depthByNode = new Map<string, Map<string, number>>();
  const prodReachable = new Set<string>();
  const directIds = new Set(roots.map(r => r.nodeId));

  for (const root of roots) {
    // Breadth-first, so the first visit to a node is at its shortest distance from the root.
    const queue: Array<[string, number]> = [[root.nodeId, 0]];
    const seen = new Set<string>();
    for (let i = 0; i < queue.length; i++) {
      const [id, depth] = queue[i];
      if (seen.has(id)) continue;
      seen.add(id);
      if (!root.dev) prodReachable.add(id);
      if (id !== root.nodeId) {
        if (!viaByNode.has(id)) viaByNode.set(id, { prod: new Set(), dev: new Set() });
        viaByNode.get(id)![root.dev ? 'dev' : 'prod'].add(root.name);
        if (!depthByNode.has(id)) depthByNode.set(id, new Map());
        const depths = depthByNode.get(id)!;
        depths.set(root.name, Math.min(depths.get(root.name) ?? Infinity, depth));
      }
      const node = nodes.get(id);
      if (node) for (const dep of node.deps) queue.push([dep, depth + 1]);
    }
  }

  type Entry = InstalledPackage & { prodVia: Set<string>; devVia: Set<string>; depths: Map<string, number> };
  const byKey = new Map<string, Entry>();
  for (const [id, node] of nodes) {
    if (!isValidVersion(node.version)) continue;
    if (!directIds.has(id) && !viaByNode.has(id)) continue;
    const key = `${node.name}@${node.version}`;
    const via = viaByNode.get(id);
    const direct = directIds.has(id);
    const dev = !prodReachable.has(id);
    const existing = byKey.get(key);
    if (existing) {
      existing.direct ||= direct;
      existing.dev &&= dev;
      via?.prod.forEach(v => existing.prodVia.add(v));
      via?.dev.forEach(v => existing.devVia.add(v));
      for (const [root, d] of depthByNode.get(id) ?? []) {
        existing.depths.set(root, Math.min(existing.depths.get(root) ?? Infinity, d));
      }
    } else {
      byKey.set(key, {
        ecosystem,
        name: node.name,
        version: node.version,
        direct,
        dev,
        via: [],
        prodVia: new Set(via?.prod),
        devVia: new Set(via?.dev),
        depths: new Map(depthByNode.get(id)),
      });
    }
  }
  const packages: InstalledPackage[] = [];
  for (const { prodVia, devVia, depths, ...pkg } of byKey.values()) {
    const via = [...new Set(pkg.dev ? [...prodVia, ...devVia] : [...prodVia])].filter(v => v !== pkg.name).sort();
    const viaDepth = Object.fromEntries(via.filter(v => depths.has(v)).map(v => [v, depths.get(v)!]));
    packages.push({ ...pkg, via, ...(Object.keys(viaDepth).length ? { viaDepth } : {}) });
  }
  return packages.sort((a, b) => a.name.localeCompare(b.name));
}
