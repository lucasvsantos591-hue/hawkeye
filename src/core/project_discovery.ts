import * as fs from 'fs';
import * as path from 'path';
import type { Ecosystem } from './versions.js';
import { NPM_LOCKFILES } from './dependency_inventory.js';
import { hasPythonManifest, hasPythonLock } from './ecosystems/python_inventory.js';
import { hasGradleManifest, hasMavenManifest } from './ecosystems/java_inventory.js';

export type ProjectKind = 'npm' | 'python' | 'maven' | 'gradle';

export interface DiscoveredProject {
  kind: ProjectKind;
  ecosystem: Ecosystem;
  /** Absolute directory of the project. */
  dir: string;
  /** Path relative to the scanned root ('.' for the root itself). */
  relDir: string;
}

const SKIP = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'target', 'coverage', 'vendor', '.venv', 'venv', 'env',
  '.tox', '.gradle', '.idea', '.next', '__pycache__', 'site-packages', 'bower_components', 'tests', 'test',
  'examples', 'example', 'fixtures', 'docs', 'samples', 'e2e',
]);
const MAX_DEPTH = 4;

/**
 * Finds the projects inside a repository. npm packages and Python projects without their own
 * lockfile, Maven modules and Gradle subprojects are covered by their parent project.
 */
export function discoverProjects(root: string, only?: ProjectKind[]): DiscoveredProject[] {
  const out: DiscoveredProject[] = [];
  const covered: Record<ProjectKind, string[]> = { npm: [], python: [], maven: [], gradle: [] };
  const isCovered = (kind: ProjectKind, dir: string) =>
    covered[kind].some(parent => dir === parent || dir.startsWith(parent + path.sep));

  const add = (kind: ProjectKind, ecosystem: Ecosystem, dir: string, standalone = false) => {
    if ((only && !only.includes(kind)) || (!standalone && isCovered(kind, dir))) return;
    out.push({ kind, ecosystem, dir, relDir: path.relative(root, dir) || '.' });
    covered[kind].push(dir);
  };

  const visit = (dir: string, depth: number) => {
    const has = (f: string) => fs.existsSync(path.join(dir, f));
    if (has('package.json')) add('npm', 'npm', dir, NPM_LOCKFILES.some(has));
    if (hasPythonManifest(dir)) add('python', 'PyPI', dir, hasPythonLock(dir));
    if (hasMavenManifest(dir)) add('maven', 'Maven', dir);
    else if (hasGradleManifest(dir)) add('gradle', 'Maven', dir);

    if (depth >= MAX_DEPTH) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory() && !SKIP.has(e.name) && !e.name.startsWith('.')) visit(path.join(dir, e.name), depth + 1);
    }
  };
  visit(root, 0);
  return out;
}
