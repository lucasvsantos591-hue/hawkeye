import { describe, it, expect, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { readNpmInventory } from '../../src/core/dependency_inventory';
import { readPythonInventory } from '../../src/core/ecosystems/python_inventory';
import { readMavenInventory } from '../../src/core/ecosystems/java_inventory';
import { CacheManager } from '../../src/core/cache_manager';
import { ProjectFs } from '../../src/core/project_fs';
import { renderMarkdownReport } from '../../src/cli/report/render-markdown';

const SECRET = 'TOP_SECRET_VALUE=hunter2';

function sandbox() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-sec-'));
  const outside = path.join(base, 'outside');
  const repo = path.join(base, 'repo');
  fs.mkdirSync(outside);
  fs.mkdirSync(repo);
  fs.writeFileSync(path.join(outside, 'creds.txt'), `${SECRET}\n`);
  return { base, outside, repo };
}

describe('file access is confined to the scanned directory', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('ignores requirements includes that escape the root', () => {
    const { repo } = sandbox();
    fs.writeFileSync(path.join(repo, 'requirements.txt'), '-r ../outside/creds.txt\nflask==2.0.0\n');
    const inv = readPythonInventory(repo, new ProjectFs(repo));

    expect(inv.packages.map(p => p.name)).toEqual(['flask']);
    expect(JSON.stringify(inv)).not.toMatch(/hunter2|top-secret|TOP_SECRET/i);
    expect(inv.warnings.join(' ')).toMatch(/outside the scanned directory/);
  });

  it('does not read a lockfile that is a symlink to a file outside the root', () => {
    const { repo, outside } = sandbox();
    fs.writeFileSync(path.join(repo, 'package.json'), '{"dependencies":{"lodash":"4.17.10"}}');
    fs.symlinkSync(path.join(outside, 'creds.txt'), path.join(repo, 'package-lock.json'));
    const inv = readNpmInventory(repo, new ProjectFs(repo));

    expect(inv.source).toBe('package.json');
    expect(JSON.stringify(inv)).not.toMatch(/hunter2|TOP_SECRET/);
  });

  it('does not follow a pom <relativePath> outside the root nor fetch invalid coordinates', async () => {
    const { repo } = sandbox();
    const fetchMock = vi.fn(async () => new Response('', { status: 404 }));
    vi.stubGlobal('fetch', fetchMock);
    fs.writeFileSync(
      path.join(repo, 'pom.xml'),
      `<project><parent><groupId>x</groupId><artifactId>creds</artifactId><version>1</version>
       <relativePath>../outside/creds.txt</relativePath></parent><artifactId>a</artifactId>
       <dependencies><dependency><groupId>../../evil</groupId><artifactId>a</artifactId><version>1</version></dependency></dependencies></project>`,
    );
    const inv = await readMavenInventory(repo, {
      allowBuildTool: false,
      includeDev: false,
      cache: new CacheManager(null),
      pfs: new ProjectFs(repo),
    });

    expect(JSON.stringify(inv)).not.toMatch(/hunter2|TOP_SECRET/);
    expect(inv.warnings.join(' ')).toMatch(/Ignored invalid Maven coordinates/);
    expect(fetchMock.mock.calls.map(c => String(c[0])).some(u => u.includes('..'))).toBe(false);
  });
});

describe('markdown report escaping', () => {
  it('neutralizes HTML, links and code-fence breakouts from advisory or AI text', () => {
    const md = renderMarkdownReport(
      {
        schema_version: '1',
        generated_at: 'now',
        project_name: 'p',
        total_vulnerabilities: 1,
        reachable_vulnerabilities: 1,
        overall_risk_score: 50,
        results: [
          {
            vulnerability: {
              cve_id: 'CVE-1',
              package: 'pkg<img src=x onerror=alert(1)>',
              current_version: '1.0.0',
              affected_versions: ['<2'],
              severity: 'HIGH',
            },
            is_reachable: true,
            reachability_level: 2,
            confidence: 80,
            reason: '[click me](https://evil.example)',
            remediation: { type: 'MINOR', description: 'x', action: 'npm i x\n```\n# injected' },
          },
        ],
      },
      { aiPowered: false },
    );

    expect(md).not.toContain('<img');
    expect(md).toContain('\\[click me\\]\\(https://evil.example\\)');
    expect(md).toContain('````bash\nnpm i x\n```\n# injected\n````');
  });
});
