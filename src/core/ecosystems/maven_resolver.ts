import * as fs from 'fs';
import * as path from 'path';
import { CacheManager } from '../cache_manager.js';
import { fetchText, mapLimit } from '../http.js';
import type { GraphNode, Root } from '../inventory_types.js';

const MAVEN_REPO = (process.env.HAWKEYE_MAVEN_REPO || 'https://repo1.maven.org/maven2').replace(/\/$/, '');
const POM_TTL = 30 * 24 * 60 * 60 * 1000;
const MAX_ARTIFACTS = 3000;

export interface MavenDep {
  groupId: string;
  artifactId: string;
  version?: string;
  scope?: string;
  type?: string;
  optional?: boolean;
  exclusions: string[];
}

export interface PomModel {
  groupId: string;
  artifactId: string;
  version: string;
  packaging: string;
  props: Record<string, string>;
  depMgmt: Map<string, MavenDep>;
  deps: MavenDep[];
  modules: string[];
  /** Inherited, not yet interpolated: children re-interpolate these with their own properties. */
  rawDepMgmt: MavenDep[];
  rawDeps: MavenDep[];
}

interface RawPom {
  groupId?: string;
  artifactId?: string;
  version?: string;
  packaging?: string;
  parent?: { groupId: string; artifactId: string; version: string; relativePath?: string };
  props: Record<string, string>;
  depMgmt: MavenDep[];
  deps: MavenDep[];
  modules: string[];
}

const open = (tag: string) => `<${tag}(?:\\s[^>]*[^/>])?>`;
const strip = (xml: string, tag: string) =>
  xml
    .replace(new RegExp(`${open(tag)}[\\s\\S]*?</${tag}>`, 'g'), '')
    .replace(new RegExp(`<${tag}(?:\\s[^>]*)?/>`, 'g'), '');
const first = (xml: string, tag: string) =>
  xml.match(new RegExp(`${open(tag)}([\\s\\S]*?)</${tag}>`))?.[1]?.trim();
const all = (xml: string, tag: string) =>
  [...xml.matchAll(new RegExp(`${open(tag)}([\\s\\S]*?)</${tag}>`, 'g'))].map(m => m[1]);

function parseDeps(xml: string | undefined): MavenDep[] {
  if (!xml) return [];
  return all(xml, 'dependency').map(block => ({
    groupId: first(block, 'groupId') ?? '',
    artifactId: first(block, 'artifactId') ?? '',
    version: first(block, 'version'),
    scope: first(block, 'scope'),
    type: first(block, 'type'),
    optional: first(block, 'optional') === 'true',
    exclusions: all(first(block, 'exclusions') ?? '', 'exclusion').map(
      e => `${first(e, 'groupId') ?? '*'}:${first(e, 'artifactId') ?? '*'}`,
    ),
  }));
}

export function parsePom(xml: string): RawPom {
  let body = xml.replace(/<!--[\s\S]*?-->/g, '');
  const parentXml = first(body, 'parent');
  body = strip(body, 'parent');
  for (const tag of ['profiles', 'build', 'reporting', 'pluginRepositories', 'repositories', 'distributionManagement']) {
    body = strip(body, tag);
  }
  const dmXml = first(body, 'dependencyManagement');
  body = strip(body, 'dependencyManagement');
  const depsXml = all(body, 'dependencies').join('\n');
  const propsXml = first(body, 'properties') ?? '';
  const modulesXml = first(body, 'modules') ?? '';
  let header = body;
  for (const tag of ['dependencies', 'properties', 'modules', 'developers', 'contributors', 'licenses', 'scm', 'organization', 'issueManagement', 'ciManagement', 'mailingLists']) {
    header = strip(header, tag);
  }
  const props: Record<string, string> = {};
  for (const m of propsXml.matchAll(/<([\w.-]+)>([^<]*)<\/\1>/g)) props[m[1]] = m[2].trim();

  return {
    groupId: first(header, 'groupId'),
    artifactId: first(header, 'artifactId'),
    version: first(header, 'version'),
    packaging: first(header, 'packaging'),
    parent: parentXml
      ? {
          groupId: first(parentXml, 'groupId') ?? '',
          artifactId: first(parentXml, 'artifactId') ?? '',
          version: first(parentXml, 'version') ?? '',
          relativePath: first(parentXml, 'relativePath'),
        }
      : undefined,
    props,
    depMgmt: parseDeps(dmXml),
    deps: parseDeps(depsXml),
    modules: all(modulesXml, 'module').map(m => m.trim()),
  };
}

function interpolate(value: string | undefined, props: Record<string, string>): string | undefined {
  if (value === undefined) return undefined;
  let out = value;
  for (let i = 0; i < 10 && out.includes('${'); i++) {
    out = out.replace(/\$\{([^}]+)\}/g, (whole, key) => props[key] ?? props[key.replace(/^pom\./, 'project.')] ?? whole);
  }
  return out;
}

export class MavenResolver {
  private models = new Map<string, Promise<PomModel | null>>();
  readonly warnings = new Set<string>();

  constructor(private cache: CacheManager) {}

  async fetchPom(g: string, a: string, v: string): Promise<string | null> {
    const key = `pom:${g}:${a}:${v}`;
    const cached = this.cache.get<string | null>(key);
    if (cached !== undefined) return cached;
    const url = `${MAVEN_REPO}/${g.replace(/\./g, '/')}/${a}/${v}/${a}-${v}.pom`;
    try {
      const xml = await fetchText(url, { retries: 2, timeoutMs: 20_000 });
      this.cache.set(key, xml, POM_TTL);
      return xml;
    } catch (error) {
      if (/HTTP 404/.test(String(error))) this.cache.set(key, null, POM_TTL);
      return null;
    }
  }

  /** Effective model of a local pom.xml (parents resolved from disk first, then Maven Central). */
  async localModel(pomPath: string): Promise<PomModel | null> {
    return this.buildModel(fs.readFileSync(pomPath, 'utf-8'), path.dirname(pomPath));
  }

  remoteModel(g: string, a: string, v: string): Promise<PomModel | null> {
    const key = `${g}:${a}:${v}`;
    if (!this.models.has(key)) {
      this.models.set(
        key,
        this.fetchPom(g, a, v).then(xml => (xml ? this.buildModel(xml) : null)),
      );
    }
    return this.models.get(key)!;
  }

  async buildModel(xml: string, dir?: string, depth = 0): Promise<PomModel | null> {
    if (depth > 12) return null;
    const raw = parsePom(xml);
    let parent: PomModel | null = null;
    if (raw.parent?.artifactId) {
      const localParent = dir ? path.resolve(dir, raw.parent.relativePath || '../pom.xml') : null;
      const parentFile = localParent && fs.existsSync(localParent) && fs.statSync(localParent).isDirectory()
        ? path.join(localParent, 'pom.xml')
        : localParent;
      if (parentFile && fs.existsSync(parentFile)) {
        const parentXml = fs.readFileSync(parentFile, 'utf-8');
        if (parsePom(parentXml).artifactId === raw.parent.artifactId) {
          parent = await this.buildModel(parentXml, path.dirname(parentFile), depth + 1);
        }
      }
      if (!parent) parent = await this.remoteModel(raw.parent.groupId, raw.parent.artifactId, raw.parent.version);
      if (!parent) this.warnings.add(`Could not load parent POM ${raw.parent.groupId}:${raw.parent.artifactId}:${raw.parent.version}`);
    }

    const groupId = raw.groupId ?? raw.parent?.groupId ?? '';
    const version = raw.version ?? raw.parent?.version ?? '';
    const props: Record<string, string> = {
      ...(parent?.props ?? {}),
      ...raw.props,
      'project.groupId': groupId,
      'project.artifactId': raw.artifactId ?? '',
      'project.version': version,
      'project.parent.version': raw.parent?.version ?? '',
      'project.parent.groupId': raw.parent?.groupId ?? '',
      version,
      groupId,
    };
    const interp = (d: MavenDep): MavenDep => ({
      ...d,
      groupId: interpolate(d.groupId, props) ?? '',
      artifactId: interpolate(d.artifactId, props) ?? '',
      version: interpolate(d.version, props),
      scope: interpolate(d.scope, props),
    });

    // Maven merges the parent chain first and interpolates afterwards, so a child's properties
    // (e.g. <commons-lang3.version>) override versions declared in a parent's dependencyManagement.
    const rawDepMgmt = [...(parent?.rawDepMgmt ?? []), ...raw.depMgmt];
    const rawDeps = [...(parent?.rawDeps ?? []), ...raw.deps];
    const explicit = rawDepMgmt.map(interp);
    const boms = explicit.filter(d => d.scope === 'import' && d.type === 'pom');
    const imported = await Promise.all(
      boms.map(b => (b.version && !b.version.includes('${') ? this.remoteModel(b.groupId, b.artifactId, b.version) : null)),
    );
    const depMgmt = new Map<string, MavenDep>();
    for (const [i, bom] of imported.entries()) {
      if (!bom) {
        this.warnings.add(`Could not load BOM ${boms[i].groupId}:${boms[i].artifactId}:${boms[i].version}`);
        continue;
      }
      for (const [key, value] of bom.depMgmt) if (!depMgmt.has(key)) depMgmt.set(key, value);
    }
    for (const d of explicit) if (d.scope !== 'import') depMgmt.set(`${d.groupId}:${d.artifactId}`, d);

    return {
      groupId,
      artifactId: raw.artifactId ?? '',
      version,
      packaging: raw.packaging ?? 'jar',
      props,
      depMgmt,
      deps: rawDeps.map(interp),
      modules: raw.modules,
      rawDepMgmt,
      rawDeps,
    };
  }

  /** Adds `managed` entries (e.g. a BOM such as spring-boot-dependencies) to a dependency-management map. */
  async importBom(depMgmt: Map<string, MavenDep>, g: string, a: string, v: string): Promise<void> {
    const bom = await this.remoteModel(g, a, v);
    if (!bom) {
      this.warnings.add(`Could not load BOM ${g}:${a}:${v}`);
      return;
    }
    for (const [key, value] of bom.depMgmt) if (!depMgmt.has(key)) depMgmt.set(key, value);
  }

  /**
   * Breadth-first resolution with Maven's "nearest wins" rule. Root dependency management
   * overrides transitive versions, as Maven does. Exclusions and optional deps are honoured.
   */
  async resolve(
    rootDeps: Array<MavenDep & { from: string }>,
    rootDepMgmt: Map<string, MavenDep>,
    localModules: Set<string>,
  ): Promise<{ nodes: Map<string, GraphNode>; roots: Root[] }> {
    const nodes = new Map<string, GraphNode>();
    const chosen = new Map<string, string>();
    const roots: Root[] = [];
    type Item = { dep: MavenDep; exclusions: string[]; dev: boolean; parentId: string | null };
    let level: Item[] = [];

    for (const d of rootDeps) {
      if (localModules.has(`${d.groupId}:${d.artifactId}`) || d.scope === 'import') continue;
      const managedEntry = rootDepMgmt.get(`${d.groupId}:${d.artifactId}`);
      const version = d.version ?? managedEntry?.version;
      const scope = d.scope ?? managedEntry?.scope;
      if (!version) {
        this.warnings.add(`No version for ${d.groupId}:${d.artifactId} (managed by an unresolved BOM?)`);
        continue;
      }
      level.push({
        dep: { ...d, version, scope },
        exclusions: [...d.exclusions, ...(managedEntry?.exclusions ?? [])],
        dev: scope === 'test',
        parentId: null,
      });
    }

    while (level.length && nodes.size < MAX_ARTIFACTS) {
      const next: Item[] = [];
      const fresh: Item[] = [];
      for (const item of level) {
        const ga = `${item.dep.groupId}:${item.dep.artifactId}`;
        const existing = chosen.get(ga);
        const id = existing ?? `${ga}@${item.dep.version}`;
        if (item.parentId) nodes.get(item.parentId)?.deps.push(id);
        else roots.push({ name: ga, nodeId: id, dev: item.dev });
        if (existing) continue;
        chosen.set(ga, id);
        nodes.set(id, { name: ga, version: item.dep.version!, deps: [] });
        fresh.push(item);
      }
      const models = await mapLimit(fresh, 12, item =>
        this.remoteModel(item.dep.groupId, item.dep.artifactId, item.dep.version!),
      );
      for (const [i, item] of fresh.entries()) {
        const model = models[i];
        if (!model) continue;
        const id = chosen.get(`${item.dep.groupId}:${item.dep.artifactId}`)!;
        for (const child of model.deps) {
          const ga = `${child.groupId}:${child.artifactId}`;
          const scope = child.scope ?? model.depMgmt.get(ga)?.scope ?? 'compile';
          if (child.optional || scope === 'test' || scope === 'provided' || scope === 'system' || scope === 'import') continue;
          if (item.exclusions.some(ex => matchesExclusion(ex, child))) continue;
          if (localModules.has(ga)) continue;
          const managed = rootDepMgmt.get(ga);
          const version = managed?.version ?? child.version ?? model.depMgmt.get(ga)?.version;
          if (!version || version.includes('${') || /^[[(]/.test(version)) continue;
          next.push({
            dep: { ...child, version },
            exclusions: [...item.exclusions, ...child.exclusions, ...(managed?.exclusions ?? [])],
            dev: item.dev || managed?.scope === 'test',
            parentId: id,
          });
        }
      }
      level = next;
    }
    if (nodes.size >= MAX_ARTIFACTS) this.warnings.add(`Stopped resolving after ${MAX_ARTIFACTS} artifacts`);
    return { nodes, roots };
  }
}

function matchesExclusion(exclusion: string, dep: MavenDep): boolean {
  const [g, a] = exclusion.split(':');
  return (g === '*' || g === dep.groupId) && (a === '*' || a === dep.artifactId);
}
