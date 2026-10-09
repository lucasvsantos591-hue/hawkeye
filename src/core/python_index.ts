import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import type { PackageUsage } from './import_index.js';
import { normalizePyName } from './versions.js';
import { ProjectFs } from './project_fs.js';
import { childEnv } from './child_env.js';

const IGNORED_DIRS = new Set([
  '.git', '.venv', 'venv', 'env', '.env', '.tox', '.nox', '__pycache__', 'site-packages', 'node_modules',
  'build', 'dist', '.eggs', '.mypy_cache', '.pytest_cache', 'htmlcov', '.idea', 'migrations',
]);
const TEST_PATH = /(^|\/)(tests?|testing)\/|(^|\/)test_[^/]*\.py$|_test\.py$|(^|\/)conftest\.py$/;
const COMMAND_FILES = /^(Dockerfile.*|Procfile|docker-compose.*\.ya?ml|compose\.ya?ml|Makefile|.*\.sh|supervisord.*\.conf|uwsgi.*\.ini|gunicorn.*\.(py|conf)|entrypoint.*|app\.ya?ml)$/i;
const MAX_SITES = 5;

/** Distribution name -> import names, for packages whose import name differs from the distribution. */
const IMPORT_NAMES: Record<string, string[]> = {
  pyyaml: ['yaml'], beautifulsoup4: ['bs4'], pillow: ['PIL'], 'scikit-learn': ['sklearn'], 'scikit-image': ['skimage'],
  'opencv-python': ['cv2'], 'opencv-python-headless': ['cv2'], 'opencv-contrib-python': ['cv2'],
  'python-dateutil': ['dateutil'], pyjwt: ['jwt'], 'python-jose': ['jose'], pycryptodome: ['Crypto'],
  pycryptodomex: ['Cryptodome'], pycrypto: ['Crypto'], mysqlclient: ['MySQLdb'], 'mysql-connector-python': ['mysql.connector'],
  'psycopg2-binary': ['psycopg2'], 'psycopg-binary': ['psycopg'], 'python-multipart': ['multipart', 'python_multipart'],
  'python-dotenv': ['dotenv'], attrs: ['attr', 'attrs'], protobuf: ['google.protobuf'], grpcio: ['grpc'],
  'google-api-python-client': ['googleapiclient'], pyopenssl: ['OpenSSL'], 'python-magic': ['magic'],
  setuptools: ['setuptools', 'pkg_resources'], 'django-cors-headers': ['corsheaders'], djangorestframework: ['rest_framework'],
  'django-filter': ['django_filters'], 'django-environ': ['environ'], 'django-storages': ['storages'],
  'python-socketio': ['socketio'], 'python-engineio': ['engineio'], 'websocket-client': ['websocket'], pyzmq: ['zmq'],
  'python-ldap': ['ldap'], pysaml2: ['saml2'], 'python3-saml': ['onelogin'], dnspython: ['dns'], pynacl: ['nacl'],
  fonttools: ['fontTools'], gitpython: ['git'], pygithub: ['github'], 'python-gitlab': ['gitlab'],
  'python-keycloak': ['keycloak'], 'apache-airflow': ['airflow'], 'msgpack-python': ['msgpack'], pywin32: ['win32api', 'win32con'],
  'python-json-logger': ['pythonjsonlogger'], 'ruamel-yaml': ['ruamel.yaml'], 'tensorflow-cpu': ['tensorflow'],
  'tensorflow-gpu': ['tensorflow'], 'jinja2-time': ['jinja2_time'], 'pdfminer-six': ['pdfminer'], 'pymupdf': ['fitz'],
  'python-docx': ['docx'], 'python-pptx': ['pptx'], 'xlrd2': ['xlrd2'], 'pyhcl': ['hcl'], 'avro-python3': ['avro'],
};

/** Packages that are commonly loaded without an import: servers started from the command line, DB drivers. */
const RUNTIME_LOADED = new Set([
  'gunicorn', 'uvicorn', 'hypercorn', 'daphne', 'waitress', 'uwsgi', 'gevent', 'eventlet', 'psycopg2', 'psycopg2-binary',
  'psycopg', 'psycopg-binary', 'pymysql', 'mysqlclient', 'mysql-connector-python', 'cx-oracle', 'oracledb', 'pyodbc',
  'asyncpg', 'aiomysql', 'aiosqlite', 'whitenoise', 'celery', 'python-multipart', 'email-validator', 'uvloop',
  'httptools', 'websockets',
]);

// Runs with -I, and drops '' / cwd from sys.path before any other import, so a module in the analyzed
// repository (an ast.py or json.py at its root) can never shadow the standard library and run.
const PY_SCRIPT = String.raw`
import sys
sys.path[:] = [p for p in sys.path if p not in ('', '.')]
import ast, json, re
IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$')
FALLBACK = re.compile(r'^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))', re.M)
def is_tc(test):
    return (isinstance(test, ast.Name) and test.id == 'TYPE_CHECKING') or (isinstance(test, ast.Attribute) and test.attr == 'TYPE_CHECKING')
def fallback(src):
    out = []
    for m in FALLBACK.finditer(src):
        line = src.count('\n', 0, m.start()) + 1
        mods = [m.group(1)] if m.group(1) else [x.strip() for x in m.group(2).split(',')]
        for mod in mods:
            out.append({'m': mod, 'l': line, 't': False, 'u': True, 'mem': [], 's': line})
    return {'imports': out, 'strings': [], 'fallback': True}
def analyze(path):
    try:
        src = open(path, 'rb').read().decode('utf-8', 'replace')
    except Exception:
        return None
    try:
        tree = ast.parse(src)
    except Exception:
        return fallback(src)
    tc = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and is_tc(node.test):
            for sub in node.body:
                for n in ast.walk(sub):
                    if hasattr(n, 'lineno'):
                        tc.add(n.lineno)
    imports, bindings = [], {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                e = {'m': a.name, 'l': node.lineno, 't': node.lineno in tc, 'u': False, 'mem': [], 's': None}
                imports.append(e)
                bindings.setdefault(a.asname or a.name.split('.')[0], []).append((e, None))
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            e = {'m': node.module, 'l': node.lineno, 't': node.lineno in tc, 'u': False, 'mem': [], 's': None}
            imports.append(e)
            for a in node.names:
                if a.name == '*':
                    e['u'] = not e['t']
                    e['s'] = node.lineno
                    continue
                e['mem'].append(a.name)
                bindings.setdefault(a.asname or a.name, []).append((e, a.name))
    strings = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in bindings:
            for e, _ in bindings[node.id]:
                if not e['t'] and not e['u']:
                    e['u'] = True
                    e['s'] = node.lineno
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in bindings:
            for e, member in bindings[node.value.id]:
                if member is None and node.attr not in e['mem'] and len(e['mem']) < 50:
                    e['mem'].append(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) <= 100 and IDENT.match(node.value):
            strings.add(node.value)
    return {'imports': imports, 'strings': sorted(strings)[:300]}
files = json.load(sys.stdin)
out = {}
for f in files:
    r = analyze(f)
    if r is not None:
        out[f] = r
json.dump(out, sys.stdout)
`;

interface PyImport {
  m: string;
  l: number;
  t: boolean;
  u: boolean;
  mem: string[];
  s: number | null;
}

interface FileResult {
  imports: PyImport[];
  strings: string[];
}

interface ModuleUsage {
  files: Set<string>;
  testFiles: Set<string>;
  used: boolean;
  valueImport: boolean;
  members: Set<string>;
  sites: string[];
}

export interface PythonIndex {
  usage(distName: string): PackageUsage | undefined;
  runtimeLoaded(distName: string): string | null;
  filesScanned: number;
  warnings: string[];
}

export function buildPythonIndex(projectPath: string): PythonIndex {
  const warnings: string[] = [];
  // Absolute paths: python3 runs from another working directory.
  const files = listPythonFiles(path.resolve(projectPath));
  const results = analyzeFiles(files, warnings);

  const modules = new Map<string, ModuleUsage>();
  const strings = new Map<string, string>();
  for (const [abs, result] of Object.entries(results)) {
    const rel = path.relative(projectPath, abs).split(path.sep).join('/');
    const isTest = TEST_PATH.test(rel);
    const configFile = /settings|config|conf/i.test(rel);
    for (const s of result.strings) {
      if (!isTest && (s.includes('.') || configFile) && !strings.has(s)) strings.set(s, rel);
    }
    for (const imp of result.imports) {
      let u = modules.get(imp.m);
      if (!u) {
        u = { files: new Set(), testFiles: new Set(), used: false, valueImport: false, members: new Set(), sites: [] };
        modules.set(imp.m, u);
      }
      (isTest ? u.testFiles : u.files).add(rel);
      if (isTest) continue;
      if (!imp.t) u.valueImport = true;
      imp.mem.forEach(m => u!.members.add(m));
      if (imp.u) {
        u.used = true;
        const site = `${rel}:${imp.s ?? imp.l}`;
        if (u.sites.length < MAX_SITES && !u.sites.includes(site)) u.sites.push(site);
      }
    }
  }

  const venvNames = readVenvTopLevel(projectPath);
  const commandText = readCommandFiles(projectPath);

  const importNames = (dist: string): string[] => {
    const n = normalizePyName(dist);
    const names = new Set<string>([...(venvNames.get(n) ?? []), ...(IMPORT_NAMES[n] ?? [])]);
    names.add(n.replace(/-/g, '_'));
    if (n.startsWith('python-')) names.add(n.slice(7).replace(/-/g, '_'));
    if (n.endsWith('-python')) names.add(n.slice(0, -7).replace(/-/g, '_'));
    if (n.includes('-')) names.add(n.replace(/-/g, '.'));
    return [...names];
  };

  return {
    filesScanned: Object.keys(results).length,
    warnings,
    usage(dist) {
      const names = importNames(dist);
      const matches = [...modules.entries()].filter(([mod]) => names.some(n => mod === n || mod.startsWith(`${n}.`)));
      const stringHit = [...strings.entries()].find(([s]) => names.some(n => s === n || s.startsWith(`${n}.`)));
      if (!matches.length && !stringHit) return undefined;

      const merged: PackageUsage = { files: [], testFiles: [], used: false, typeOnly: true, members: [], sites: [] };
      const files = new Set<string>();
      const testFiles = new Set<string>();
      const members = new Set<string>();
      for (const [mod, u] of matches) {
        u.files.forEach(f => files.add(f));
        u.testFiles.forEach(f => testFiles.add(f));
        u.members.forEach(m => members.add(m));
        const sub = names.map(n => (mod.startsWith(`${n}.`) ? mod.slice(n.length + 1) : '')).find(Boolean);
        if (sub) members.add(sub);
        if (u.valueImport) merged.typeOnly = false;
        if (u.used) merged.used = true;
        for (const s of u.sites) if (merged.sites.length < MAX_SITES) merged.sites.push(s);
      }
      if (stringHit && !merged.used) {
        merged.used = true;
        merged.typeOnly = false;
        files.add(stringHit[1]);
        members.add(`"${stringHit[0]}" (string reference, e.g. Django INSTALLED_APPS)`);
        merged.sites.push(stringHit[1]);
      }
      merged.files = [...files].sort();
      merged.testFiles = [...testFiles].sort();
      merged.members = [...members].sort();
      return merged;
    },
    runtimeLoaded(dist) {
      const n = normalizePyName(dist);
      for (const name of [n, ...importNames(n)]) {
        const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const hit = commandText.find(({ text }) => new RegExp(`(^|[\\s"'\\[/=])${escaped}($|[\\s"':\\]])`, 'm').test(text));
        if (hit) return `Invoked from ${hit.file}`;
      }
      return RUNTIME_LOADED.has(n) ? 'Server or database driver that is normally loaded without an import' : null;
    },
  };
}

function listPythonFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!IGNORED_DIRS.has(e.name) && !e.name.startsWith('.')) walk(path.join(dir, e.name));
      } else if (e.isFile() && e.name.endsWith('.py')) {
        const file = path.join(dir, e.name);
        try {
          if (fs.statSync(file).size <= 2_000_000) out.push(file);
        } catch {
          // skip unreadable
        }
      }
    }
  };
  walk(root);
  return out;
}

function analyzeFiles(files: string[], warnings: string[]): Record<string, FileResult> {
  if (!files.length) return {};
  for (const python of ['python3', 'python']) {
    const res = spawnSync(python, ['-I', '-c', PY_SCRIPT], {
      input: JSON.stringify(files),
      maxBuffer: 1024 * 1024 * 1024,
      encoding: 'utf-8',
      timeout: 10 * 60 * 1000,
      cwd: os.tmpdir(),
      env: childEnv('python'),
    });
    if (res.status === 0 && res.stdout) {
      try {
        return JSON.parse(res.stdout);
      } catch {
        // fall through
      }
    }
  }
  warnings.push('python3 not found: Python imports detected with a regex (usage not tracked, level 1 only)');
  const out: Record<string, FileResult> = {};
  const re = /^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))/gm;
  for (const file of files) {
    const src = fs.readFileSync(file, 'utf-8');
    const imports: PyImport[] = [];
    for (const m of src.matchAll(re)) {
      const line = src.slice(0, m.index).split('\n').length;
      const mods = m[1] ? [m[1]] : m[2].split(',').map(s => s.trim());
      for (const mod of mods) imports.push({ m: mod, l: line, t: false, u: true, mem: [], s: line });
    }
    out[file] = { imports, strings: [] };
  }
  return out;
}

/** Reads top_level.txt / RECORD from a virtualenv inside the project to learn exact import names. */
function readVenvTopLevel(root: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const pfs = new ProjectFs(root);
  for (const venv of ['.venv', 'venv', 'env']) {
    const libDirs = [path.join(root, venv, 'lib'), path.join(root, venv, 'Lib')];
    for (const lib of libDirs) {
      if (!pfs.isDirectory(lib)) continue;
      const siteDirs = fs.readdirSync(lib).map(d => path.join(lib, d, 'site-packages'));
      siteDirs.push(path.join(lib, 'site-packages'));
      for (const site of siteDirs) {
        if (!fs.existsSync(site)) continue;
        for (const entry of fs.readdirSync(site)) {
          if (!entry.endsWith('.dist-info')) continue;
          const name = normalizePyName(entry.replace(/-[^-]+\.dist-info$/, ''));
          const top = path.join(site, entry, 'top_level.txt');
          const record = path.join(site, entry, 'RECORD');
          let names: string[] = [];
          if (fs.existsSync(top)) names = fs.readFileSync(top, 'utf-8').split(/\r?\n/).filter(Boolean);
          else if (fs.existsSync(record)) {
            names = [
              ...new Set(
                fs
                  .readFileSync(record, 'utf-8')
                  .split(/\r?\n/)
                  .map(l => l.split(',')[0])
                  .filter(p => p.endsWith('.py') && !p.includes('.dist-info') && !p.startsWith('..'))
                  .map(p => p.split('/')[0].replace(/\.py$/, '')),
              ),
            ];
          }
          if (names.length) out.set(name, names);
        }
      }
    }
  }
  return out;
}

function readCommandFiles(root: string): Array<{ file: string; text: string }> {
  const out: Array<{ file: string; text: string }> = [];
  const walk = (dir: string, depth: number) => {
    if (depth > 3) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!IGNORED_DIRS.has(e.name) && !e.name.startsWith('.')) walk(full, depth + 1);
      } else if (COMMAND_FILES.test(e.name)) {
        try {
          if (fs.statSync(full).size < 500_000) {
            out.push({ file: path.relative(root, full).split(path.sep).join('/'), text: fs.readFileSync(full, 'utf-8') });
          }
        } catch {
          // skip
        }
      }
    }
  };
  walk(root, 0);
  return out;
}
