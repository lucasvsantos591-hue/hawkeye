import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { buildImportIndex, type ImportIndex } from '../../src/core/import_index';

const files: Record<string, string> = {
  'src/app.js': `
    const _ = require('lodash');
    const { sign } = require('jsonwebtoken');
    const unused = require('left-pad');
    module.exports = (t) => { sign({}, 'k'); return _.template(t); };
  `,
  'src/server.ts': `
    import express from 'express';
    import type { AxiosInstance } from 'axios';
    import { merge } from 'deepmerge';
    import get from 'lodash/get';
    import 'reflect-metadata';
    export * from '@scope/utils';
    export const x: AxiosInstance | null = null;
    const app = express();
    app.use(express.json());
    export async function load() { return import('chalk'); }
  `,
  'src/view.tsx': `import React from 'react'; export const V = () => <div>{React.version}</div>;`,
  'test/app.test.js': `const moment = require('moment'); moment();`,
  'node_modules/lodash/index.js': `require('should-not-be-indexed')`,
  'dist/bundle.js': `require('also-not-indexed')`,
};

describe('buildImportIndex', () => {
  let index: ImportIndex;

  beforeAll(() => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-idx-'));
    for (const [rel, code] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.writeFileSync(path.join(root, rel), code);
    }
    index = buildImportIndex(root);
  });

  it('detects used CommonJS and ESM imports with the members accessed', () => {
    expect(index.get('lodash')).toMatchObject({ used: true, typeOnly: false });
    expect(index.get('lodash')!.members).toEqual(expect.arrayContaining(['template', 'get']));
    expect(index.get('lodash')!.sites[0]).toMatch(/^src\/app\.js:\d+$/);
    expect(index.get('jsonwebtoken')).toMatchObject({ used: true, members: ['sign'] });
    expect(index.get('express')).toMatchObject({ used: true, members: ['json'] });
    expect(index.get('react')).toMatchObject({ used: true });
  });

  it('treats side-effect imports, re-exports and dynamic imports as used', () => {
    expect(index.get('reflect-metadata')?.used).toBe(true);
    expect(index.get('@scope/utils')?.used).toBe(true);
    expect(index.get('chalk')?.used).toBe(true);
  });

  it('distinguishes unused, type-only and test-only imports', () => {
    expect(index.get('left-pad')).toMatchObject({ used: false, typeOnly: false });
    expect(index.get('deepmerge')).toMatchObject({ used: false });
    expect(index.get('axios')).toMatchObject({ used: false, typeOnly: true });
    expect(index.get('moment')).toMatchObject({ used: false, files: [], testFiles: ['test/app.test.js'] });
  });

  it('skips node_modules and build output', () => {
    expect(index.get('should-not-be-indexed')).toBeUndefined();
    expect(index.get('also-not-indexed')).toBeUndefined();
    expect(index.filesScanned).toBe(4);
  });
});
