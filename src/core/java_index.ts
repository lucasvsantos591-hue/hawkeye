import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { PackageUsage } from './import_index.js';

const IGNORED_DIRS = new Set(['.git', 'target', 'build', 'out', '.gradle', '.idea', 'node_modules', 'bin', '.mvn']);
const TEST_PATH = /(^|\/)src\/(test|it|integrationTest|testFixtures)\/|(^|\/)tests?\/|(Test|Tests|IT)\.(java|kt)$/;
const MAX_SITES = 5;

/** groupId:artifactId -> Java packages, for artifacts whose packages don't follow their coordinates. */
const KNOWN_PACKAGES: Record<string, string[]> = {
  'commons-io:commons-io': ['org.apache.commons.io'],
  'commons-lang:commons-lang': ['org.apache.commons.lang'],
  'commons-collections:commons-collections': ['org.apache.commons.collections'],
  'commons-codec:commons-codec': ['org.apache.commons.codec'],
  'commons-fileupload:commons-fileupload': ['org.apache.commons.fileupload'],
  'commons-beanutils:commons-beanutils': ['org.apache.commons.beanutils'],
  'commons-httpclient:commons-httpclient': ['org.apache.commons.httpclient'],
  'com.google.guava:guava': ['com.google.common', 'com.google.thirdparty'],
  'com.fasterxml.jackson.core:jackson-databind': ['com.fasterxml.jackson.databind'],
  'com.fasterxml.jackson.core:jackson-core': ['com.fasterxml.jackson.core'],
  'com.fasterxml.jackson.core:jackson-annotations': ['com.fasterxml.jackson.annotation'],
  'log4j:log4j': ['org.apache.log4j'],
  'org.apache.logging.log4j:log4j-core': ['org.apache.logging.log4j.core'],
  'org.apache.logging.log4j:log4j-api': ['org.apache.logging.log4j'],
  'org.yaml:snakeyaml': ['org.yaml.snakeyaml'],
  'com.h2database:h2': ['org.h2'],
  'mysql:mysql-connector-java': ['com.mysql'],
  'com.mysql:mysql-connector-j': ['com.mysql'],
  'com.google.code.gson:gson': ['com.google.gson'],
  'ch.qos.logback:logback-classic': ['ch.qos.logback.classic'],
  'ch.qos.logback:logback-core': ['ch.qos.logback.core'],
  'org.springframework:spring-webmvc': ['org.springframework.web.servlet'],
  'org.springframework:spring-web': ['org.springframework.web', 'org.springframework.http'],
  'org.springframework:spring-core': ['org.springframework.core', 'org.springframework.util'],
  'org.springframework:spring-context': ['org.springframework.context', 'org.springframework.stereotype', 'org.springframework.scheduling', 'org.springframework.cache'],
  'org.apache.tomcat.embed:tomcat-embed-core': ['org.apache.catalina', 'org.apache.tomcat', 'org.apache.coyote'],
  'com.thoughtworks.xstream:xstream': ['com.thoughtworks.xstream'],
  'org.apache.httpcomponents:httpclient': ['org.apache.http'],
  'org.apache.httpcomponents:httpcore': ['org.apache.http'],
  'org.apache.httpcomponents.client5:httpclient5': ['org.apache.hc.client5'],
  'com.squareup.okhttp3:okhttp': ['okhttp3'],
  'com.auth0:java-jwt': ['com.auth0.jwt'],
  'org.apache.struts:struts2-core': ['org.apache.struts2', 'com.opensymphony.xwork2'],
  'org.bouncycastle:bcprov-jdk15on': ['org.bouncycastle'],
  'org.bouncycastle:bcprov-jdk18on': ['org.bouncycastle'],
  'org.jsoup:jsoup': ['org.jsoup'],
  'io.projectreactor.netty:reactor-netty-http': ['reactor.netty'],
  'io.projectreactor:reactor-core': ['reactor'],
  'org.jetbrains.kotlin:kotlin-stdlib': ['kotlin'],
  'junit:junit': ['org.junit', 'junit.framework'],
  'org.mockito:mockito-core': ['org.mockito'],
  'org.javassist:javassist': ['javassist'],
  'dom4j:dom4j': ['org.dom4j'],
  'org.dom4j:dom4j': ['org.dom4j'],
};

export interface JavaIndex {
  usage(ga: string, version: string): PackageUsage | undefined;
  filesScanned: number;
}

interface ImportRecord {
  pkg: string;
  cls: string;
  site: string;
  test: boolean;
  file: string;
}

export function buildJavaIndex(projectPath: string): JavaIndex {
  const files = listSources(projectPath);
  const imports: ImportRecord[] = [];
  const importRe = /^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*?)(\.\*)?\s*(?:as\s+\w+)?\s*;?\s*$/;

  for (const abs of files) {
    const rel = path.relative(projectPath, abs).split(path.sep).join('/');
    const test = TEST_PATH.test(rel);
    let text: string;
    try {
      text = fs.readFileSync(abs, 'utf-8');
    } catch {
      continue;
    }
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(importRe);
      if (!m) {
        if (/^\s*(public|private|protected|class|interface|enum|object|fun|abstract|final|data|sealed)\b/.test(lines[i])) break;
        continue;
      }
      const segments = m[1].split('.');
      const clsIndex = m[2] ? -1 : segments.findIndex(s => /^[A-Z]/.test(s));
      const pkg = (clsIndex > 0 ? segments.slice(0, clsIndex) : segments).join('.');
      const cls = clsIndex > 0 ? segments.slice(clsIndex).join('.') : '*';
      imports.push({ pkg, cls, site: `${rel}:${i + 1}`, test, file: rel });
    }
  }

  const jarCache = new Map<string, Set<string> | null>();
  return {
    filesScanned: files.length,
    usage(ga, version) {
      const key = `${ga}@${version}`;
      if (!jarCache.has(key)) jarCache.set(key, jarPackages(ga, version));
      const exact = jarCache.get(key);
      const prefixes = exact ? null : candidatePrefixes(ga);
      const matches = imports.filter(imp =>
        exact ? exact.has(imp.pkg) : prefixes!.some(p => imp.pkg === p || imp.pkg.startsWith(`${p}.`)),
      );
      if (!matches.length) return undefined;
      const prod = matches.filter(m => !m.test);
      return {
        files: [...new Set(prod.map(m => m.file))].sort(),
        testFiles: [...new Set(matches.filter(m => m.test).map(m => m.file))].sort(),
        used: prod.length > 0,
        typeOnly: false,
        members: [...new Set(prod.map(m => (m.cls === '*' ? `${m.pkg}.*` : m.cls)))].sort().slice(0, 30),
        sites: prod.slice(0, MAX_SITES).map(m => m.site),
      };
    },
  };
}

function listSources(root: string): string[] {
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
      } else if (e.isFile() && /\.(java|kt)$/.test(e.name)) {
        out.push(path.join(dir, e.name));
      }
    }
  };
  walk(root);
  return out;
}

function candidatePrefixes(ga: string): string[] {
  if (KNOWN_PACKAGES[ga]) return KNOWN_PACKAGES[ga];
  const [g, a] = ga.split(':');
  const out = new Set<string>([g]);
  const tokens = a.split(/[-_.]/).filter(t => t && !/^(core|api|impl|java|jdk\d*\w*|all|spring|boot|starter)$/.test(t));
  if (tokens.length) out.add(`${g}.${tokens.join('.')}`);
  return [...out];
}

/** Lists the Java packages inside an artifact's jar, if it is in the local Maven or Gradle cache. */
function jarPackages(ga: string, version: string): Set<string> | null {
  const [g, a] = ga.split(':');
  const home = os.homedir();
  const candidates = [path.join(home, '.m2', 'repository', ...g.split('.'), a, version, `${a}-${version}.jar`)];
  const gradleDir = path.join(home, '.gradle', 'caches', 'modules-2', 'files-2.1', g, a, version);
  if (fs.existsSync(gradleDir)) {
    for (const hash of fs.readdirSync(gradleDir)) candidates.push(path.join(gradleDir, hash, `${a}-${version}.jar`));
  }
  for (const jar of candidates) {
    if (!fs.existsSync(jar)) continue;
    const names = zipEntryNames(jar);
    if (!names) continue;
    const pkgs = new Set<string>();
    for (const name of names) {
      if (!name.endsWith('.class') || name.startsWith('META-INF/') || name === 'module-info.class') continue;
      const slash = name.lastIndexOf('/');
      if (slash > 0) pkgs.add(name.slice(0, slash).replace(/\//g, '.'));
    }
    return pkgs;
  }
  return null;
}

function zipEntryNames(file: string): string[] | null {
  try {
    const buf = fs.readFileSync(file);
    let eocd = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
      if (buf.readUInt32LE(i) === 0x06054b50) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) return null;
    const count = buf.readUInt16LE(eocd + 10);
    let offset = buf.readUInt32LE(eocd + 16);
    const names: string[] = [];
    for (let i = 0; i < count && offset + 46 <= buf.length; i++) {
      if (buf.readUInt32LE(offset) !== 0x02014b50) break;
      const nameLen = buf.readUInt16LE(offset + 28);
      const extraLen = buf.readUInt16LE(offset + 30);
      const commentLen = buf.readUInt16LE(offset + 32);
      names.push(buf.toString('utf-8', offset + 46, offset + 46 + nameLen));
      offset += 46 + nameLen + extraLen + commentLen;
    }
    return names;
  } catch {
    return null;
  }
}
