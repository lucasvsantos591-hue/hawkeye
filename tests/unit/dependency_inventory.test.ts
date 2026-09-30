import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { readDependencyInventory } from '../../src/core/dependency_inventory';

const fixtures = path.join(process.cwd(), 'tests/fixtures/lockfiles');

describe('readDependencyInventory', () => {
  for (const [dir, source] of [
    ['npm', 'package-lock.json'],
    ['pnpm', 'pnpm-lock.yaml'],
    ['yarn', 'yarn.lock'],
    ['berry', 'yarn.lock'],
  ] as const) {
    it(`reads installed versions and dependency paths from ${dir}`, () => {
      const inv = readDependencyInventory(path.join(fixtures, dir));
      const find = (name: string) => inv.packages.find(p => p.name === name);

      expect(inv.source).toBe(source);
      expect(find('express')).toMatchObject({ version: '4.16.0', direct: true, dev: false, via: [] });
      expect(find('lodash')).toMatchObject({ version: '4.17.10', direct: true, dev: false });
      expect(find('qs')).toMatchObject({ version: '6.5.1', direct: false, dev: false });
      expect(find('qs')!.via).toContain('express');
      expect(find('mocha')).toMatchObject({ direct: true, dev: true });
      expect(find('commander')).toMatchObject({ direct: false, dev: true, via: ['mocha'] });
    });
  }

  it('falls back to package.json ranges with a warning when there is no lockfile', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-inv-'));
    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({ dependencies: { lodash: '^4.17.10', local: 'file:../x' }, devDependencies: { mocha: '~5.0.0' } }),
    );
    const inv = readDependencyInventory(dir);

    expect(inv.source).toBe('package.json');
    expect(inv.packages).toEqual([
      { name: 'lodash', version: '4.17.10', direct: true, dev: false, via: [] },
      { name: 'mocha', version: '5.0.0', direct: true, dev: true, via: [] },
    ]);
    expect(inv.warnings.join(' ')).toMatch(/No usable lockfile/);
  });

  it('reads package-lock v1 nested dependencies', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-inv-'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { a: '^1.0.0' } }));
    fs.writeFileSync(
      path.join(dir, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          a: { version: '1.2.0', requires: { b: '^2.0.0' }, dependencies: { b: { version: '2.1.0' } } },
          b: { version: '1.0.0' },
        },
      }),
    );
    const inv = readDependencyInventory(dir);

    expect(inv.packages).toEqual([
      { name: 'a', version: '1.2.0', direct: true, dev: false, via: [] },
      { name: 'b', version: '2.1.0', direct: false, dev: false, via: ['a'] },
    ]);
  });
});
