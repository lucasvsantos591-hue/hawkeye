import { describe, it, expect, afterEach, beforeAll, afterAll, vi } from 'vitest';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import type { AddressInfo } from 'net';
import { buildPythonIndex } from '../../src/core/python_index';
import { childEnv } from '../../src/core/child_env';
import { AnalysisEngine } from '../../src/core/analysis_engine';
import { createServer } from '../../src/cli/server';

/** Scanning a repository must never run code from it, unless the user opts into its build tool. */

function repo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-untrusted-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

const hasPython = spawnSync('python3', ['--version']).status === 0;

describe('Python analysis of an untrusted repository', () => {
  const cwd = process.cwd();
  afterEach(() => process.chdir(cwd));

  it.skipIf(!hasPython)('does not import modules from the repository that shadow the standard library', () => {
    const marker = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-marker-')), 'pwned');
    const payload = `open(${JSON.stringify(marker)}, "w").write("pwned")\n`;
    const dir = repo({
      'ast.py': payload,
      'json.py': payload,
      're.py': payload,
      'app.py': 'import requests\nrequests.get("https://example.com")\n',
    });

    // The usual invocation: `cd repo && hawkeye analyze .`
    process.chdir(dir);
    const index = buildPythonIndex('.');

    expect(fs.existsSync(marker)).toBe(false);
    // The real AST analysis ran (not the regex fallback that a crashed python3 leads to).
    expect(index.warnings.join('\n')).not.toContain('python3 not found');
    expect(index.usage('requests')).toMatchObject({ used: true, members: ['get'] });
  });
});

describe('environment of child processes', () => {
  const env = {
    PATH: '/usr/bin',
    HOME: '/home/u',
    JAVA_HOME: '/opt/jdk',
    HTTPS_PROXY: 'http://proxy:3128',
    HAWKEYE_API_TOKEN: 'api-token',
    ANTHROPIC_API_KEY: 'sk-ant',
    AWS_SECRET_ACCESS_KEY: 'aws',
    GITHUB_TOKEN: 'ghp',
  };

  it('passes what a build needs and none of the caller secrets', () => {
    expect(childEnv('build', env)).toEqual({
      PATH: '/usr/bin',
      HOME: '/home/u',
      JAVA_HOME: '/opt/jdk',
      HTTPS_PROXY: 'http://proxy:3128',
    });
  });

  it('gives python3 even less', () => {
    expect(childEnv('python', env)).toEqual({ PATH: '/usr/bin', HOME: '/home/u' });
  });
});

describe('build tools are opt-in', () => {
  afterEach(() => vi.unstubAllGlobals());

  const fakeFetch = async () =>
    new Response(JSON.stringify({ results: [], vulns: [], vulnerabilities: [], data: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });

  function mavenRepoWithWrapper() {
    const marker = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-marker-')), 'mvnw-ran');
    const dir = repo({
      'pom.xml':
        '<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>app</artifactId><version>1</version></project>',
      mvnw: `#!/bin/sh\necho ran > ${JSON.stringify(marker)}\nexit 1\n`,
    });
    fs.chmodSync(path.join(dir, 'mvnw'), 0o755);
    return { dir, marker };
  }

  it.skipIf(process.platform === 'win32')('does not run ./mvnw unless asked to', async () => {
    vi.stubGlobal('fetch', vi.fn(fakeFetch));
    const { dir, marker } = mavenRepoWithWrapper();

    const result = await new AnalysisEngine({ projectPath: dir, cacheDir: null }).analyze();

    expect(fs.existsSync(marker)).toBe(false);
    expect(result.scan?.warnings.join('\n')).toContain('Build tools disabled');
  });

  it.skipIf(process.platform === 'win32')('runs it with allowBuildTool: true', async () => {
    vi.stubGlobal('fetch', vi.fn(fakeFetch));
    const { dir, marker } = mavenRepoWithWrapper();

    await new AnalysisEngine({ projectPath: dir, cacheDir: null, allowBuildTool: true }).analyze();

    expect(fs.existsSync(marker)).toBe(true);
  });
});

describe('API server', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-api-')));
  const sample = JSON.parse(
    fs.readFileSync(path.join(__dirname, '../fixtures/analysis-results/sample-basic.json'), 'utf-8'),
  );
  const servers: http.Server[] = [];

  async function start(token = ''): Promise<number> {
    const server = createServer({ token, allowedRoot: root });
    servers.push(server);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    return (server.address() as AddressInfo).port;
  }

  function request(
    port: number,
    opts: { method?: string; path: string; host?: string; headers?: Record<string, string>; body?: string },
  ): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          method: opts.method ?? 'GET',
          path: opts.path,
          headers: { Host: opts.host ?? `localhost:${port}`, ...opts.headers },
        },
        res => {
          let body = '';
          res.on('data', chunk => (body += chunk));
          res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
        },
      );
      req.on('error', reject);
      req.end(opts.body);
    });
  }

  const json = { 'Content-Type': 'application/json' };
  const reportBody = JSON.stringify({ analysisResult: sample, format: 'json' });

  let open: number;
  beforeAll(async () => {
    open = await start();
  });
  afterAll(() => servers.forEach(s => s.close()));

  it('without a token, rejects requests whose Host is not localhost (DNS rebinding)', async () => {
    for (const host of ['evil.example', 'evil.example:3000', '127.0.0.1.nip.io']) {
      const res = await request(open, { path: '/api/health', host });
      expect(res.status).toBe(421);
    }
    for (const host of [`localhost:${open}`, `127.0.0.1:${open}`, `[::1]:${open}`, 'localhost']) {
      expect((await request(open, { path: '/api/health', host })).status).toBe(200);
    }
  });

  it('accepts only application/json bodies, so a cross-site form or text/plain post cannot reach it', async () => {
    for (const type of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x']) {
      const res = await request(open, {
        method: 'POST',
        path: '/api/report',
        headers: { 'Content-Type': type },
        body: reportBody,
      });
      expect(res.status).toBe(415);
    }
    const ok = await request(open, {
      method: 'POST',
      path: '/api/report',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: reportBody,
    });
    expect(ok.status).toBe(200);
    expect(JSON.parse(ok.body).total_vulnerabilities).toBe(sample.total_vulnerabilities);
  });

  it('keeps projectPath inside the allowed root', async () => {
    const res = await request(open, {
      method: 'POST',
      path: '/api/analyze',
      headers: json,
      body: JSON.stringify({ projectPath: os.tmpdir() }),
    });
    expect(res.status).toBe(403);
  });

  it('with a token, accepts any Host (reverse proxy) but requires the bearer token', async () => {
    const port = await start('s3cret');
    const host = 'hawkeye.internal.example';
    expect((await request(port, { method: 'POST', path: '/api/report', host, headers: json, body: reportBody })).status).toBe(401);
    const res = await request(port, {
      method: 'POST',
      path: '/api/report',
      host,
      headers: { ...json, Authorization: 'Bearer s3cret' },
      body: reportBody,
    });
    expect(res.status).toBe(200);
  });
});
