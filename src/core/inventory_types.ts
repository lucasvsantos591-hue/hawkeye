import type { Ecosystem } from './versions.js';

export interface InstalledPackage {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
  /** Direct dependencies that pull this package in (for a direct dep: other direct deps that also need it). */
  via: string[];
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
  const viaByNode = new Map<string, Set<string>>();
  const prodReachable = new Set<string>();
  const directIds = new Set(roots.map(r => r.nodeId));

  for (const root of roots) {
    const queue = [root.nodeId];
    const seen = new Set<string>();
    while (queue.length) {
      const id = queue.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      if (!root.dev) prodReachable.add(id);
      if (id !== root.nodeId) {
        if (!viaByNode.has(id)) viaByNode.set(id, new Set());
        viaByNode.get(id)!.add(root.name);
      }
      const node = nodes.get(id);
      if (node) queue.push(...node.deps);
    }
  }

  const byKey = new Map<string, InstalledPackage>();
  for (const [id, node] of nodes) {
    if (!isValidVersion(node.version)) continue;
    if (!directIds.has(id) && !viaByNode.has(id)) continue;
    const key = `${node.name}@${node.version}`;
    const via = [...(viaByNode.get(id) ?? [])];
    const direct = directIds.has(id);
    const dev = !prodReachable.has(id);
    const existing = byKey.get(key);
    if (existing) {
      existing.direct ||= direct;
      existing.dev &&= dev;
      existing.via = [...new Set([...existing.via, ...via])];
    } else {
      byKey.set(key, { ecosystem, name: node.name, version: node.version, direct, dev, via });
    }
  }
  for (const pkg of byKey.values()) {
    pkg.via = pkg.via.filter(v => v !== pkg.name).sort();
  }
  return [...byKey.values()].sort((a, b) => a.name.localeCompare(b.name));
}
