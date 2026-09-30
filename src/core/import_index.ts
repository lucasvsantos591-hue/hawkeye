import * as fs from 'fs';
import * as path from 'path';
import { parse, type ParserPlugin } from '@babel/parser';
import traverseModule, { type NodePath } from '@babel/traverse';
import * as t from '@babel/types';

const traverse: typeof traverseModule =
  (traverseModule as unknown as { default?: typeof traverseModule }).default ?? traverseModule;

const SOURCE_EXT = /\.(?:[cm]?[jt]sx?)$/;
const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt', '.svelte-kit',
  '.output', '.turbo', '.cache', '.vercel', 'vendor', 'bower_components', 'storybook-static',
]);
const TEST_PATH = /(^|\/)(__tests__|__mocks__|tests?|spec|e2e|cypress|playwright)(\/|$)|\.(test|spec|stories)\.[cm]?[jt]sx?$/;
const MAX_FILE_BYTES = 1_000_000;
const MAX_SITES = 5;

export interface PackageUsage {
  /** Files (relative) that import the package, excluding test-only files. */
  files: string[];
  testFiles: string[];
  /** At least one non-type import whose binding is actually referenced (or a side-effect import). */
  used: boolean;
  /** Only `import type` / type positions reference the package. */
  typeOnly: boolean;
  /** Members accessed on the package, e.g. `template` for `_.template(...)`. */
  members: string[];
  /** Up to 5 `file:line` locations where the package is used. */
  sites: string[];
}

interface MutableUsage {
  files: Set<string>;
  testFiles: Set<string>;
  used: boolean;
  valueImport: boolean;
  members: Set<string>;
  sites: string[];
}

export interface ImportIndex {
  get(packageName: string): PackageUsage | undefined;
  filesScanned: number;
  parseErrors: string[];
}

export function buildImportIndex(projectPath: string): ImportIndex {
  const usages = new Map<string, MutableUsage>();
  const parseErrors: string[] = [];
  const files = listSourceFiles(projectPath);

  for (const abs of files) {
    const rel = path.relative(projectPath, abs).split(path.sep).join('/');
    const isTest = TEST_PATH.test(rel);
    let code: string;
    try {
      code = fs.readFileSync(abs, 'utf-8');
    } catch {
      continue;
    }
    const ast = parseSource(code, rel);
    if (!ast) {
      parseErrors.push(rel);
      continue;
    }
    collectFileUsages(ast, rel, isTest, usages);
  }

  return {
    filesScanned: files.length,
    parseErrors,
    get(name) {
      const u = usages.get(name);
      if (!u) return undefined;
      return {
        files: [...u.files].sort(),
        testFiles: [...u.testFiles].sort(),
        used: u.used,
        typeOnly: !u.valueImport,
        members: [...u.members].sort(),
        sites: u.sites,
      };
    },
  };
}

function listSourceFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) walk(path.join(dir, entry.name));
      } else if (
        entry.isFile() &&
        SOURCE_EXT.test(entry.name) &&
        !entry.name.endsWith('.d.ts') &&
        !entry.name.endsWith('.min.js')
      ) {
        const file = path.join(dir, entry.name);
        try {
          if (fs.statSync(file).size <= MAX_FILE_BYTES) out.push(file);
        } catch {
          // unreadable file: skip
        }
      }
    }
  };
  walk(root);
  return out;
}

function parseSource(code: string, rel: string): t.File | null {
  const isTs = /\.[cm]?tsx?$/.test(rel);
  const attempts: ParserPlugin[][] = isTs
    ? [['typescript', 'jsx', 'decorators-legacy'], ['typescript', 'decorators-legacy']]
    : [['jsx', 'flow', 'decorators-legacy'], ['typescript', 'jsx', 'decorators-legacy']];
  for (const plugins of attempts) {
    try {
      return parse(code, {
        sourceType: 'unambiguous',
        allowReturnOutsideFunction: true,
        allowImportExportEverywhere: true,
        allowAwaitOutsideFunction: true,
        errorRecovery: true,
        plugins,
      });
    } catch {
      // try next plugin set
    }
  }
  return null;
}

function packageName(specifier: string): string | null {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/') || specifier.includes(':')) return null;
  const parts = specifier.split('/');
  if (specifier.startsWith('@')) return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  return parts[0];
}

function collectFileUsages(ast: t.File, rel: string, isTest: boolean, usages: Map<string, MutableUsage>) {
  const usageFor = (name: string): MutableUsage => {
    let u = usages.get(name);
    if (!u) {
      u = { files: new Set(), testFiles: new Set(), used: false, valueImport: false, members: new Set(), sites: [] };
      usages.set(name, u);
    }
    return u;
  };

  const record = (specifier: string, subpath: string | null, node: t.Node, typeOnly: boolean) => {
    const name = packageName(specifier);
    if (!name) return null;
    const u = usageFor(name);
    (isTest ? u.testFiles : u.files).add(rel);
    if (!typeOnly && !isTest) u.valueImport = true;
    if (subpath) u.members.add(subpath);
    return { u, node };
  };

  const markUsed = (u: MutableUsage, node: t.Node) => {
    if (isTest) return;
    u.used = true;
    if (u.sites.length < MAX_SITES) {
      const site = `${rel}:${node.loc?.start.line ?? 0}`;
      if (!u.sites.includes(site)) u.sites.push(site);
    }
  };

  const subpathOf = (specifier: string) => {
    const name = packageName(specifier);
    return name && specifier.length > name.length ? specifier.slice(name.length + 1) : null;
  };

  const trackBinding = (u: MutableUsage, scopePath: NodePath, localName: string, member: string | null) => {
    const binding = scopePath.scope.getBinding(localName);
    const refs = binding?.referencePaths ?? [];
    for (const ref of refs) {
      if (ref.parentPath?.isTSTypeReference() || ref.findParent(p => p.isTSType())) continue;
      markUsed(u, ref.node);
      if (member) u.members.add(member);
      const parent = ref.parentPath;
      if (parent?.isMemberExpression() && parent.node.object === ref.node) {
        const prop = parent.node.property;
        if (t.isIdentifier(prop) && !parent.node.computed) u.members.add(prop.name);
        else if (t.isStringLiteral(prop)) u.members.add(prop.value);
      }
    }
  };

  traverse(ast, {
    ImportDeclaration(p) {
      const spec = p.node.source.value;
      const typeOnly = p.node.importKind === 'type' || p.node.importKind === 'typeof';
      const hit = record(spec, subpathOf(spec), p.node, typeOnly);
      if (!hit || typeOnly) return;
      if (p.node.specifiers.length === 0) {
        markUsed(hit.u, p.node);
        return;
      }
      for (const s of p.node.specifiers) {
        if (t.isImportSpecifier(s) && s.importKind === 'type') continue;
        const member = t.isImportSpecifier(s)
          ? t.isIdentifier(s.imported) ? s.imported.name : s.imported.value
          : null;
        trackBinding(hit.u, p, s.local.name, member);
      }
    },
    ExportNamedDeclaration(p) {
      if (!p.node.source || p.node.exportKind === 'type') return;
      const hit = record(p.node.source.value, subpathOf(p.node.source.value), p.node, false);
      if (hit) markUsed(hit.u, p.node);
    },
    ExportAllDeclaration(p) {
      if (p.node.exportKind === 'type') return;
      const hit = record(p.node.source.value, subpathOf(p.node.source.value), p.node, false);
      if (hit) markUsed(hit.u, p.node);
    },
    TSImportEqualsDeclaration(p) {
      const ref = p.node.moduleReference;
      if (!t.isTSExternalModuleReference(ref)) return;
      const hit = record(ref.expression.value, subpathOf(ref.expression.value), p.node, p.node.importKind === 'type');
      if (hit && p.node.importKind !== 'type') trackBinding(hit.u, p, p.node.id.name, null);
    },
    CallExpression(p) {
      const { callee, arguments: args } = p.node;
      const arg = args[0];
      if (!t.isStringLiteral(arg) && !(t.isTemplateLiteral(arg) && arg.expressions.length === 0)) return;
      const spec = t.isStringLiteral(arg) ? arg.value : arg.quasis[0].value.cooked ?? '';
      const isRequire = t.isIdentifier(callee, { name: 'require' }) && !p.scope.hasBinding('require');
      const isDynamicImport = t.isImport(callee);
      if (!isRequire && !isDynamicImport) return;
      const hit = record(spec, subpathOf(spec), p.node, false);
      if (!hit) return;

      const parent = p.parentPath;
      if (isRequire && parent.isVariableDeclarator() && parent.node.init === p.node) {
        const id = parent.node.id;
        if (t.isIdentifier(id)) {
          trackBinding(hit.u, parent, id.name, null);
          return;
        }
        if (t.isObjectPattern(id)) {
          for (const prop of id.properties) {
            if (t.isObjectProperty(prop) && t.isIdentifier(prop.value)) {
              const key = t.isIdentifier(prop.key) ? prop.key.name : t.isStringLiteral(prop.key) ? prop.key.value : null;
              trackBinding(hit.u, parent, prop.value.name, key);
            } else if (t.isRestElement(prop) && t.isIdentifier(prop.argument)) {
              trackBinding(hit.u, parent, prop.argument.name, null);
            }
          }
          return;
        }
      }
      if (parent.isMemberExpression() && parent.node.object === p.node) {
        const prop = parent.node.property;
        if (t.isIdentifier(prop) && !parent.node.computed) hit.u.members.add(prop.name);
      }
      markUsed(hit.u, p.node);
    },
  });
}
