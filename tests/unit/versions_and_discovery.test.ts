import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { compareVersions, normalizePyName } from '../../src/core/versions';
import { cvss3BaseScore } from '../../src/adapters/vulnerability_sources/osv_source';
import { discoverProjects } from '../../src/core/project_discovery';

describe('compareVersions', () => {
  it.each([
    ['PyPI', '2.0.0rc1', '2.0.0', -1],
    ['PyPI', '1.0.post1', '1.0', 1],
    ['PyPI', '1.10', '1.9', 1],
    ['PyPI', '1.0', '1.0.0', 0],
    ['Maven', '1.0-SNAPSHOT', '1.0', -1],
    ['Maven', '31.1-jre', '32.0.0-jre', -1],
    ['Maven', '2.17.0', '2.17.0-rc1', 1],
    ['Maven', '5.3.20.RELEASE', '5.3.9.RELEASE', 1],
    ['npm', '1.2.3-beta.1', '1.2.3', -1],
  ] as const)('%s %s vs %s', (eco, a, b, expected) => {
    expect(Math.sign(compareVersions(eco, a, b))).toBe(expected);
  });

  it('normalizes Python distribution names (PEP 503)', () => {
    expect(normalizePyName('Django_REST.framework')).toBe('django-rest-framework');
  });
});

describe('cvss3BaseScore', () => {
  it('computes base scores for common vectors', () => {
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H')).toBe(7.2);
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe(6.1);
    expect(cvss3BaseScore('CVSS:4.0/AV:N')).toBeNull();
  });
});

describe('discoverProjects', () => {
  it('finds npm, Python and Java projects in a monorepo without double-counting modules', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-disc-'));
    const files: Record<string, string> = {
      'package.json': '{"workspaces":["web"]}',
      'package-lock.json': '{}',
      'web/package.json': '{}',
      'backend/pom.xml': '<project/>',
      'backend/api/pom.xml': '<project/>',
      'services/worker/requirements.txt': 'celery==5.0.0',
      'services/gradle-svc/settings.gradle': '',
      'services/gradle-svc/core/build.gradle': '',
      'node_modules/x/package.json': '{}',
      'tests/fixture/package.json': '{}',
    };
    for (const [rel, content] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.writeFileSync(path.join(root, rel), content);
    }
    const found = discoverProjects(root).map(p => `${p.kind}:${p.relDir}`).sort();

    expect(found).toEqual(['gradle:services/gradle-svc', 'maven:backend', 'npm:.', 'python:services/worker']);
  });
});
