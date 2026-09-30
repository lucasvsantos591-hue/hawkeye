import { describe, it, expect, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parseMavenTree, parseGradleTree, parseGradleBuildFiles, readMavenInventory } from '../../src/core/ecosystems/java_inventory';
import { buildJavaIndex } from '../../src/core/java_index';
import { CacheManager } from '../../src/core/cache_manager';

const fixtures = path.join(process.cwd(), 'tests/fixtures/java');
const find = (pkgs: any[], name: string) => pkgs.find(p => p.name === name);

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-java-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

describe('parseMavenTree (real WebGoat output)', () => {
  const pkgs = parseMavenTree(fs.readFileSync(path.join(fixtures, 'webgoat-mvn-tree.txt'), 'utf-8'));

  it('reads direct and transitive artifacts with scopes', () => {
    expect(find(pkgs, 'com.thoughtworks.xstream:xstream')).toMatchObject({ version: '1.4.5', direct: true, dev: false });
    expect(find(pkgs, 'org.apache.tomcat.embed:tomcat-embed-core')).toMatchObject({ direct: false, dev: false });
    expect(find(pkgs, 'org.apache.tomcat.embed:tomcat-embed-core').via.length).toBeGreaterThan(0);
    expect(find(pkgs, 'org.springframework.boot:spring-boot-starter-test')).toMatchObject({ dev: true });
    expect(pkgs.filter(p => !p.dev)).toHaveLength(191);
  });
});

describe('parseGradleTree (real petclinic output)', () => {
  it('reads resolved versions ("a -> b") and skips constraints', () => {
    const pkgs = parseGradleTree(fs.readFileSync(path.join(fixtures, 'petclinic-gradle-tree.txt'), 'utf-8'));
    expect(find(pkgs, 'org.apache.tomcat.embed:tomcat-embed-core')).toMatchObject({ version: '11.0.22', direct: false });
    expect(find(pkgs, 'org.springframework.boot:spring-boot-starter-webmvc')).toMatchObject({ version: '4.1.0', direct: true });
    expect(pkgs.every(p => !p.version.includes('->'))).toBe(true);
  });
});

describe('parseGradleBuildFiles', () => {
  it('reads string, map and version-catalog notations plus the Spring Boot BOM', () => {
    const dir = project({
      'build.gradle.kts': `plugins { id("org.springframework.boot") version "3.2.0" }
val jacksonVersion = "2.15.0"
dependencies {
  implementation("org.springframework.boot:spring-boot-starter-web")
  implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
  implementation(group = "org.yaml", name = "snakeyaml", version = "1.30")
  implementation(libs.commons.text)
  testImplementation("junit:junit:4.12")
}`,
      'gradle/libs.versions.toml': `[versions]
text = "1.9"
[libraries]
commons-text = { module = "org.apache.commons:commons-text", version.ref = "text" }
`,
    });
    const declared = parseGradleBuildFiles(dir);
    const byName = Object.fromEntries(declared.deps.map(d => [`${d.groupId}:${d.artifactId}`, d]));

    expect(declared.boms).toContain('org.springframework.boot:spring-boot-dependencies:3.2.0');
    expect(byName['org.springframework.boot:spring-boot-starter-web'].version).toBeUndefined();
    expect(byName['com.fasterxml.jackson.core:jackson-databind'].version).toBe('2.15.0');
    expect(byName['org.yaml:snakeyaml'].version).toBe('1.30');
    expect(byName['org.apache.commons:commons-text'].version).toBe('1.9');
    expect(byName['junit:junit'].scope).toBe('test');
  });
});

describe('readMavenInventory without Maven (POM resolver)', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('resolves parent properties, imported BOMs, transitive deps, exclusions and managed scopes', async () => {
    const poms: Record<string, string> = {
      'com/acme/parent/1.0/parent-1.0.pom': `<project><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version>
        <properties><lib.version>2.0</lib.version><build-helper.version>1</build-helper.version></properties>
        <dependencyManagement><dependencies>
          <dependency><groupId>com.acme</groupId><artifactId>lib</artifactId><version>\${lib.version}</version></dependency>
          <dependency><groupId>com.acme</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency>
        </dependencies></dependencyManagement></project>`,
      'com/acme/bom/1.0/bom-1.0.pom': `<project><groupId>com.acme</groupId><artifactId>bom</artifactId><version>1.0</version>
        <dependencyManagement><dependencies>
          <dependency><groupId>com.acme</groupId><artifactId>util</artifactId><version>3.0</version></dependency>
        </dependencies></dependencyManagement></project>`,
      'com/acme/lib/2.5/lib-2.5.pom': `<project><groupId>com.acme</groupId><artifactId>lib</artifactId><version>2.5</version>
        <dependencies>
          <dependency><groupId>com.acme</groupId><artifactId>util</artifactId><version>1.0</version></dependency>
          <dependency><groupId>com.acme</groupId><artifactId>excluded</artifactId><version>1.0</version></dependency>
          <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency>
          <dependency><groupId>com.acme</groupId><artifactId>opt</artifactId><version>1.0</version><optional>true</optional></dependency>
        </dependencies></project>`,
      'com/acme/util/3.0/util-3.0.pom': `<project><groupId>com.acme</groupId><artifactId>util</artifactId><version>3.0</version></project>`,
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const key = Object.keys(poms).find(k => url.endsWith(k));
        return key ? new Response(poms[key], { status: 200 }) : new Response('', { status: 404 });
      }),
    );
    const dir = project({
      'pom.xml': `<project>
        <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
        <artifactId>app</artifactId>
        <properties><lib.version>2.5</lib.version></properties>
        <dependencies>
          <dependency><groupId>com.acme</groupId><artifactId>lib</artifactId>
            <exclusions><exclusion><groupId>com.acme</groupId><artifactId>excluded</artifactId></exclusion></exclusions>
          </dependency>
        </dependencies>
        <build><plugins><plugin><artifactId>x</artifactId><dependencies><dependency><groupId>no</groupId><artifactId>plugin-dep</artifactId><version>1</version></dependency></dependencies></plugin></plugins></build>
      </project>`,
    });
    const inv = await readMavenInventory(dir, { allowBuildTool: false, includeDev: false, cache: new CacheManager(null) });
    const names = inv.packages.map(p => `${p.name}@${p.version}`).sort();

    // lib version comes from the child's property overriding the parent's; util is pinned by the imported BOM.
    expect(names).toEqual(['com.acme:lib@2.5', 'com.acme:util@3.0']);
    expect(find(inv.packages, 'com.acme:util')).toMatchObject({ direct: false, via: ['com.acme:lib'] });
  });
});

describe('buildJavaIndex', () => {
  it('maps imports to artifacts and separates test sources', () => {
    const dir = project({
      'src/main/java/app/Api.java': `package app;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;
import static org.apache.commons.lang3.StringUtils.isBlank;
public class Api {}`,
      'src/main/kotlin/app/Util.kt': `@file:JvmName("U")
package app
import com.google.common.collect.ImmutableList as IL
fun x() = IL.of(1)`,
      'src/test/java/app/ApiTest.java': 'package app;\nimport org.junit.Test;\npublic class ApiTest {}',
    });
    const index = buildJavaIndex(dir);

    expect(index.usage('com.fasterxml.jackson.core:jackson-databind', '2.15.0')).toMatchObject({
      used: true,
      members: ['ObjectMapper'],
      sites: ['src/main/java/app/Api.java:2'],
    });
    expect(index.usage('org.yaml:snakeyaml', '1.30')?.used).toBe(true);
    expect(index.usage('org.apache.commons:commons-lang3', '3.12.0')?.members).toEqual(['StringUtils.isBlank']);
    expect(index.usage('com.google.guava:guava', '31.0-jre')?.used).toBe(true);
    expect(index.usage('junit:junit', '4.13')).toMatchObject({ used: false, testFiles: ['src/test/java/app/ApiTest.java'] });
    expect(index.usage('com.h2database:h2', '2.0')).toBeUndefined();
  });
});
