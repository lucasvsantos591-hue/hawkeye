import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AnalysisEngine } from '../../src/core/analysis_engine';
import { HTMLReportRenderer } from '../../src/adapters/report/html_renderer';
import { SARIFRenderer } from '../../src/adapters/report/sarif_renderer';
import { epssLookup, kevLookup } from '../../src/core/threat_intel';
import { epssStatusOf, kevStatusOf } from '../../src/adapters/report/threat_labels';
import { renderMarkdownReport } from '../../src/cli/report/render-markdown';

const advisories: Record<string, any> = {
  'GHSA-lodash': {
    id: 'GHSA-lodash',
    summary: 'Command Injection in lodash <script>alert(1)</script>',
    aliases: ['CVE-2021-23337'],
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'lodash', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
      },
    ],
  },
  'GHSA-qs': {
    id: 'GHSA-qs',
    summary: 'qs prototype pollution',
    aliases: ['CVE-2022-24999'],
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'qs', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '6.5.0' }, { fixed: '6.5.3' }] }],
      },
    ],
  },
  'GHSA-axios': {
    id: 'GHSA-axios',
    summary: 'axios SSRF',
    aliases: ['CVE-2021-3749'],
    database_specific: { severity: 'MODERATE' },
    affected: [
      {
        package: { name: 'axios', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.6.0' }] }],
      },
    ],
  },
};

advisories['PYSEC-yaml'] = {
  id: 'PYSEC-yaml',
  summary: 'PyYAML arbitrary code execution',
  aliases: ['CVE-2020-14343'],
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [
    { package: { name: 'PyYAML', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '5.4' }] }] },
  ],
};
advisories['GHSA-markupsafe'] = {
  id: 'GHSA-markupsafe',
  summary: 'markupsafe issue',
  aliases: [],
  database_specific: { severity: 'LOW' },
  affected: [
    { package: { name: 'markupsafe', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.0.0rc1' }] }] },
  ],
};

advisories['GHSA-starlette'] = {
  id: 'GHSA-starlette',
  summary: 'Starlette Host header poisons request.url.path',
  aliases: ['CVE-2026-48710'],
  database_specific: { severity: 'MODERATE' },
  affected: [
    { package: { name: 'starlette', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] },
  ],
};
advisories['GHSA-anyio'] = {
  id: 'GHSA-anyio',
  summary: 'AnyIO TLS certificate spoofing',
  aliases: ['CVE-2026-63374'],
  database_specific: { severity: 'LOW' },
  affected: [
    { package: { name: 'anyio', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.14.2' }] }] },
  ],
};

const vulnsByPackage: Record<string, string[]> = {
  'starlette@0.48.0': ['GHSA-starlette'],
  'anyio@4.13.0': ['GHSA-anyio'],
  'pyyaml@5.3': ['PYSEC-yaml'],
  'markupsafe@1.1.1': ['GHSA-markupsafe'],
  'lodash@4.17.10': ['GHSA-lodash'],
  'qs@6.5.1': ['GHSA-qs'],
  'axios@0.21.0': ['GHSA-axios'],
};

function fakeFetch(url: string, init?: { body?: string }) {
  const json = (body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
  if (url.endsWith('/querybatch')) {
    const { queries } = JSON.parse(init!.body!);
    return json({
      results: queries.map((q: any) => ({
        vulns: (vulnsByPackage[`${q.package.name}@${q.version}`] ?? []).map(id => ({ id, modified: '2026-01-01' })),
      })),
    });
  }
  const vulnMatch = url.match(/\/vulns\/(.+)$/);
  if (vulnMatch) return json(advisories[decodeURIComponent(vulnMatch[1])]);
  if (url.includes('epss')) {
    return json({ data: [{ cve: 'CVE-2021-23337', epss: '0.21333', percentile: '0.97528' }] });
  }
  if (url.includes('known_exploited')) {
    return json({
      catalogVersion: '2026.10.04',
      dateReleased: '2026-10-04T18:52:56.0635Z',
      vulnerabilities: [{ cveID: 'CVE-2022-24999', dateAdded: '2026-09-02' }],
    });
  }
  return Promise.resolve(new Response('not found', { status: 404 }));
}

function makeProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-engine-'));
  fs.copyFileSync(path.join(process.cwd(), 'tests/fixtures/lockfiles/npm/package.json'), path.join(dir, 'package.json'));
  fs.copyFileSync(
    path.join(process.cwd(), 'tests/fixtures/lockfiles/npm/package-lock.json'),
    path.join(dir, 'package-lock.json'),
  );
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(
    path.join(dir, 'src/index.js'),
    `const express = require('express');\nconst _ = require('lodash');\nconst app = express();\napp.post('/r', (req, res) => res.send(_.template(req.body.t)()));\n`,
  );
  fs.writeFileSync(path.join(dir, 'src/types.ts'), `import type { AxiosInstance } from 'axios';\nexport type A = AxiosInstance;\n`);
  return dir;
}

describe('AnalysisEngine', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn(fakeFetch)));
  afterEach(() => vi.unstubAllGlobals());

  it('reports real advisories for installed versions with reachability and threat intel', async () => {
    const result = await new AnalysisEngine({ projectPath: makeProject(), cacheDir: null }).analyze();
    const byPkg = Object.fromEntries(result.results.map(f => [f.vulnerability.package, f]));

    expect(result.total_vulnerabilities).toBe(3);
    expect(result.reachable_vulnerabilities).toBe(2);
    expect(result.scan).toMatchObject({
      dependency_source: '.: package-lock.json',
      include_dev: false,
      projects: [{ path: '.', kind: 'npm', ecosystem: 'npm' }],
    });

    expect(byPkg.lodash).toMatchObject({
      is_reachable: true,
      reachability_level: 2,
      vulnerability: {
        cve_id: 'CVE-2021-23337',
        advisory_id: 'GHSA-lodash',
        current_version: '4.17.10',
        fixed_version: '4.17.21',
        severity: 'HIGH',
        dependency_type: 'direct',
        epss_score: 21.33,
        epss_status: 'scored',
        is_exploited_in_wild: false,
        kev_status: 'not_listed',
      },
      remediation: { action: 'npm install lodash@^4.17.21', type: 'MINOR' },
    });
    expect(byPkg.lodash.evidence?.members).toContain('template');

    expect(byPkg.qs).toMatchObject({
      is_reachable: true,
      vulnerability: {
        dependency_type: 'transitive',
        introduced_via: ['express'],
        is_exploited_in_wild: true,
        kev_status: 'listed',
        kev_date_added: '2026-09-02',
      },
    });
    expect(byPkg.qs.remediation.action).toContain('overrides.qs');

    expect(byPkg.axios).toMatchObject({
      is_reachable: false,
      vulnerability: { severity: 'MEDIUM', fixed_version: '1.6.0' },
    });
    expect(byPkg.axios.reason).toMatch(/type imports/);

    // KEV-listed reachable finding sorts first.
    expect(result.results[0].vulnerability.package).toBe('qs');
    expect(result.scan!.threat_intel).toEqual({
      epss: { source: expect.stringContaining('epss'), status: 'checked' },
      kev: {
        source: expect.stringContaining('known_exploited'),
        status: 'checked',
        catalog_version: '2026.10.04',
        date_released: '2026-10-04T18:52:56.0635Z',
        entries: 1,
      },
    });
  });

  it('states the KEV result for every finding in HTML, Markdown and SARIF', async () => {
    const result = await new AnalysisEngine({ projectPath: makeProject(), cacheDir: null }).analyze();

    const html = new HTMLReportRenderer(result).render();
    expect(html.match(/Not listed: no known exploitation/g)).toHaveLength(2);
    expect(html).toContain('Listed: exploited in the wild (added 2026-09-02)');
    expect(html).toContain('CISA KEV: catalog 2026.10.04 (1 CVEs) checked. 1 listed, 2 not listed, 0 without a CVE id.');
    // EPSS only scores lodash: the other two say so instead of showing nothing.
    expect(html).toContain('21.33% · p98');
    expect(html.match(/Not scored yet: FIRST EPSS has no score for this CVE/g)).toHaveLength(2);
    expect(html).toContain('FIRST EPSS checked. 1 scored, 2 not scored yet, 0 without a CVE id.');

    const md = renderMarkdownReport(result, { aiPowered: false });
    expect(md.match(/\*\*CISA KEV:\*\* /g)).toHaveLength(3);
    expect(md.match(/\*\*EPSS:\*\* /g)).toHaveLength(3);

    const sarif = JSON.parse(new SARIFRenderer(result).render());
    expect(sarif.runs[0].tool.driver.rules.map((r: any) => r.properties.kev_status).sort()).toEqual([
      'listed',
      'not_listed',
      'not_listed',
    ]);
  });

  it('marks KEV as not checked, never as not listed, when the catalog cannot be fetched', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string, init?: any) =>
        url.includes('known_exploited') ? Promise.resolve(new Response('down', { status: 503 })) : fakeFetch(url, init),
      ),
    );
    const result = await new AnalysisEngine({ projectPath: makeProject(), cacheDir: null }).analyze();

    expect(result.results.map(f => f.vulnerability.kev_status)).toEqual(['not_checked', 'not_checked', 'not_checked']);
    expect(result.results.every(f => f.vulnerability.is_exploited_in_wild === false)).toBe(true);
    expect(result.scan!.threat_intel!.kev.status).toBe('failed');
    expect(new HTMLReportRenderer(result).render()).toContain('Not checked: catalog lookup failed');
  });

  it('never makes up EPSS scores when the EPSS API fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string, init?: any) =>
        url.includes('epss') ? Promise.resolve(new Response('down', { status: 400 })) : fakeFetch(url, init),
      ),
    );
    const result = await new AnalysisEngine({ projectPath: makeProject(), cacheDir: null }).analyze();

    expect(result.results.every(f => f.vulnerability.epss_score === undefined)).toBe(true);
    expect(result.results.every(f => f.vulnerability.epss_status === 'not_checked')).toBe(true);
    expect(result.scan!.threat_intel!.epss!.status).toBe('failed');
    expect(result.scan!.warnings.join(' ')).toMatch(/EPSS lookup failed/);
    expect(new HTMLReportRenderer(result).render()).toContain('Not checked: EPSS lookup failed');
  });

  it('escapes advisory text in HTML and points SARIF at the usage site', async () => {
    const result = await new AnalysisEngine({ projectPath: makeProject(), cacheDir: null }).analyze();

    const html = new HTMLReportRenderer(result).render();
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');

    const sarif = JSON.parse(new SARIFRenderer(result).render());
    const lodash = sarif.runs[0].results.find((r: any) => r.ruleId === 'GHSA-lodash');
    expect(lodash.locations[0].physicalLocation.artifactLocation.uri).toBe('src/index.js');
  });

  it('scans Python sub-projects next to npm and inherits reachability through pip-compile parents', async () => {
    const dir = makeProject();
    fs.mkdirSync(path.join(dir, 'api'));
    fs.writeFileSync(
      path.join(dir, 'api/requirements.txt'),
      'jinja2==2.11.3\n    # via -r requirements.in\nmarkupsafe==1.1.1\n    # via jinja2\npyyaml==5.3\n    # via -r requirements.in\n',
    );
    fs.writeFileSync(path.join(dir, 'api/app.py'), 'import yaml\nfrom jinja2 import Template\nTemplate(yaml.load(open("x")))\n');
    const result = await new AnalysisEngine({ projectPath: dir, cacheDir: null }).analyze();
    const byPkg = Object.fromEntries(result.results.map(f => [f.vulnerability.package, f]));

    expect(result.scan!.projects!.map(p => `${p.kind}:${p.path}`).sort()).toEqual(['npm:.', 'python:api']);
    expect(byPkg.pyyaml).toMatchObject({
      is_reachable: true,
      vulnerability: { ecosystem: 'PyPI', project: 'api', severity: 'CRITICAL', fixed_version: '5.4' },
      remediation: { action: 'Set pyyaml==5.4 (or newer) in requirements.txt and reinstall' },
    });
    expect(byPkg.pyyaml.evidence?.sites[0]).toBe('api/app.py:3');
    expect(byPkg.markupsafe).toMatchObject({
      is_reachable: true,
      vulnerability: { dependency_type: 'transitive', introduced_via: ['jinja2'], fixed_version: '2.0.0rc1' },
    });
    // GHSA-markupsafe has no CVE alias, so KEV cannot list it.
    expect(byPkg.markupsafe.vulnerability.kev_status).toBe('no_cve');
    expect(byPkg.markupsafe.vulnerability.epss_status).toBe('no_cve');
  });
});

/**
 * Same shape as the cia-backend scan: an internal logging library that depends on fastapi, fastapi and httpx
 * as direct dependencies too, and respx (an httpx mock) only in the dev group.
 */
function makeFastApiProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-fastapi-'));
  const pkg = (name: string, version: string, deps: string[] = []) =>
    `[[package]]\nname = "${name}"\nversion = "${version}"\nsource = { registry = "https://pypi.org/simple" }\n` +
    (deps.length ? `dependencies = [${deps.map(d => `{ name = "${d}" }`).join(', ')}]\n` : '');
  fs.writeFileSync(
    path.join(dir, 'pyproject.toml'),
    '[project]\nname = "svc"\ndependencies = ["cia-logger-lib", "fastapi", "httpx"]\n[dependency-groups]\ndev = ["respx"]\n',
  );
  fs.writeFileSync(
    path.join(dir, 'uv.lock'),
    [
      'version = 1\n[[package]]\nname = "svc"\nversion = "0.1.0"\nsource = { editable = "." }\n' +
        'dependencies = [{ name = "cia-logger-lib" }, { name = "fastapi" }, { name = "httpx" }]\n' +
        '[package.dev-dependencies]\ndev = [{ name = "respx" }]\n',
      pkg('cia-logger-lib', '2.0.0', ['fastapi']),
      pkg('fastapi', '0.115.0', ['starlette']),
      pkg('starlette', '0.48.0', ['anyio']),
      pkg('httpx', '0.28.0', ['anyio']),
      pkg('anyio', '4.13.0'),
      pkg('respx', '0.22.0', ['httpx']),
    ].join('\n'),
  );
  fs.mkdirSync(path.join(dir, 'app'));
  // The logging library is used in more files than fastapi: file count must not decide the parent.
  for (const name of ['a', 'b', 'c']) {
    fs.writeFileSync(path.join(dir, `app/${name}.py`), 'from cia_logger_lib import configure_logging\nconfigure_logging()\n');
  }
  fs.writeFileSync(path.join(dir, 'app/main.py'), 'from fastapi import FastAPI\napp = FastAPI()\n');
  fs.writeFileSync(path.join(dir, 'app/client.py'), 'import httpx\nhttpx.get("https://x")\n');
  return dir;
}

describe('transitive parents (cia-backend shape)', () => {
  beforeEach(() => vi.stubGlobal('fetch', vi.fn(fakeFetch)));
  afterEach(() => vi.unstubAllGlobals());

  it('credits the closest reachable parent, names the others and leaves dev-only parents out', async () => {
    const result = await new AnalysisEngine({ projectPath: makeFastApiProject(), cacheDir: null }).analyze();
    const byPkg = Object.fromEntries(result.results.map(f => [f.vulnerability.package, f]));

    expect(byPkg.starlette.vulnerability.introduced_via).toEqual(['cia-logger-lib', 'fastapi']);
    expect(byPkg.starlette.call_chain?.path).toEqual(['fastapi', 'starlette']);
    expect(byPkg.starlette.reason).toMatch(/^Transitive dependency of fastapi, which is reachable/);
    expect(byPkg.starlette.reason).toContain('Also pulled in by cia-logger-lib, which is reachable too.');

    // respx is a dev-only mock library: never shown as the source of a production package.
    expect(byPkg.anyio.vulnerability.introduced_via).toEqual(['cia-logger-lib', 'fastapi', 'httpx']);
    expect(byPkg.anyio.vulnerability.is_dev).toBe(false);
    expect(byPkg.anyio.call_chain?.path).toEqual(['httpx', 'anyio']);
    expect(byPkg.anyio.reason).toContain('Also pulled in by fastapi, cia-logger-lib, which are reachable too.');
    expect(byPkg.anyio.remediation.description).not.toContain('respx');
  });

  it('counts LOW findings and keeps local paths out of the result and reports', async () => {
    const dir = makeFastApiProject();
    const result = await new AnalysisEngine({ projectPath: dir, cacheDir: null }).analyze();

    expect(result.summary).toMatchObject({ medium_reachable: 1, low_reachable: 1 });
    const html = new HTMLReportRenderer(result).render();
    expect(html).toMatch(/Low Severity<\/div>\s*<div class="summary-value">1</);

    // The scan ran outside the working directory: no absolute path anywhere in the output.
    expect(result.project_path).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain(dir);
    expect(html).not.toContain(dir);
    expect(new SARIFRenderer(result).render()).not.toContain(dir);
  });

  it('hides the absolute path of results written by older versions', async () => {
    const result = await new AnalysisEngine({ projectPath: makeFastApiProject(), cacheDir: null }).analyze();
    const legacy = { ...result, project_path: 'C:\\Users\\someone\\AppData\\Local\\Temp\\svc' };
    delete (legacy.summary as any).low_reachable;

    const html = new HTMLReportRenderer(legacy).render();
    expect(html).not.toContain('someone');
    expect(html).toMatch(/Low Severity<\/div>\s*<div class="summary-value">1</);
    expect(new SARIFRenderer(legacy).render()).not.toContain('someone');
  });
});

describe('EPSS status', () => {
  it('uses CVE aliases and tells "no score yet" apart from "not checked" and "no CVE"', () => {
    const scores = new Map([['CVE-2024-0002', { score: 1.5, percentile: 80 }]]);
    expect(epssLookup(['CVE-2024-0001', 'CVE-2024-0002'], scores)).toEqual({
      status: 'scored',
      score: { score: 1.5, percentile: 80 },
    });
    expect(epssLookup(['CVE-2024-0001'], scores)).toEqual({ status: 'not_scored' });
    expect(epssLookup(['CVE-2024-0001'], null)).toEqual({ status: 'not_checked' });
    expect(epssLookup(['GHSA-x'], scores)).toEqual({ status: 'no_cve' });
  });

  it('infers the status of results written before epss_status existed', () => {
    const base = { package: 'p', current_version: '1', affected_versions: [], severity: 'HIGH' as const };
    const ok = { scan: { warnings: [] } } as any;
    expect(epssStatusOf({ ...base, cve_id: 'CVE-1', epss_score: 0.5 }, ok)).toBe('scored');
    expect(epssStatusOf({ ...base, cve_id: 'CVE-1' }, ok)).toBe('not_scored');
    expect(epssStatusOf({ ...base, cve_id: 'GHSA-1', aliases: [] }, ok)).toBe('no_cve');
    const failed = { scan: { warnings: ['EPSS lookup failed: HTTP 400'] } } as any;
    expect(epssStatusOf({ ...base, cve_id: 'CVE-1' }, failed)).toBe('not_checked');
  });
});

describe('KEV status', () => {
  const catalog = { entries: new Map([['CVE-2024-0002', '2025-01-10']]) };

  it('matches CVE aliases, not only the main CVE id', () => {
    expect(kevLookup(['CVE-2024-0001', 'GHSA-x', 'CVE-2024-0002'], catalog)).toEqual({
      status: 'listed',
      date_added: '2025-01-10',
    });
    expect(kevLookup(['CVE-2024-0001'], catalog)).toEqual({ status: 'not_listed' });
    expect(kevLookup(['GHSA-x'], catalog)).toEqual({ status: 'no_cve' });
    expect(kevLookup(['CVE-2024-0001'], null)).toEqual({ status: 'not_checked' });
  });

  it('infers the status of results written before kev_status existed', () => {
    const base = { package: 'p', current_version: '1', affected_versions: [], severity: 'HIGH' as const };
    const result = { scan: { warnings: [] } } as any;
    expect(kevStatusOf({ ...base, cve_id: 'CVE-1', is_exploited_in_wild: true }, result)).toBe('listed');
    expect(kevStatusOf({ ...base, cve_id: 'CVE-1', is_exploited_in_wild: false }, result)).toBe('not_listed');
    expect(kevStatusOf({ ...base, cve_id: 'GHSA-1', aliases: [], is_exploited_in_wild: false }, result)).toBe('no_cve');
    expect(kevStatusOf({ ...base, cve_id: 'CVE-1' }, result)).toBe('not_checked');
    const failed = { scan: { warnings: ['CISA KEV lookup failed: HTTP 503'] } } as any;
    expect(kevStatusOf({ ...base, cve_id: 'CVE-1', is_exploited_in_wild: false }, failed)).toBe('not_checked');
  });
});
