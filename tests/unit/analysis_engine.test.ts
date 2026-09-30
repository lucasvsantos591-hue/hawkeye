import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AnalysisEngine } from '../../src/core/analysis_engine';
import { HTMLReportRenderer } from '../../src/adapters/report/html_renderer';
import { SARIFRenderer } from '../../src/adapters/report/sarif_renderer';

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

const vulnsByPackage: Record<string, string[]> = {
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
  if (url.includes('known_exploited')) return json({ vulnerabilities: [{ cveID: 'CVE-2022-24999' }] });
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
    expect(result.scan).toMatchObject({ dependency_source: 'package-lock.json', include_dev: false });

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
        is_exploited_in_wild: false,
      },
      remediation: { action: 'npm install lodash@^4.17.21', type: 'MINOR' },
    });
    expect(byPkg.lodash.evidence?.members).toContain('template');

    expect(byPkg.qs).toMatchObject({
      is_reachable: true,
      vulnerability: { dependency_type: 'transitive', introduced_via: ['express'], is_exploited_in_wild: true },
    });
    expect(byPkg.qs.remediation.action).toContain('overrides.qs');

    expect(byPkg.axios).toMatchObject({
      is_reachable: false,
      vulnerability: { severity: 'MEDIUM', fixed_version: '1.6.0' },
    });
    expect(byPkg.axios.reason).toMatch(/type imports/);

    // KEV-listed reachable finding sorts first.
    expect(result.results[0].vulnerability.package).toBe('qs');
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
    expect(result.scan!.warnings.join(' ')).toMatch(/EPSS lookup failed/);
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
});
