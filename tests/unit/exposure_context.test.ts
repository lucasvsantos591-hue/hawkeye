import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import JSZip from 'jszip';
import { ContextLoader } from '../../src/adapters/context/context_loader';
import { runReportPipeline } from '../../src/cli/commands/report';
import type { ExposureContext } from '../../src/types/context';

const SAMPLE = path.join(process.cwd(), 'tests/fixtures/analysis-results/sample-basic.json');

const detected: ExposureContext = {
  is_internet_facing: true,
  detection_confidence: 90,
  detection_methods: ['DNS', 'SSL'],
  dns_records: { a_records: ['203.0.113.10'] },
};

function tmpDir(files: Record<string, string> = {}): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hawkeye-exposure-'));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  return dir;
}

describe('exposure from hawkeye expose', () => {
  const cwd = process.cwd();
  afterEach(() => process.chdir(cwd));

  it('raises the exposure to internet-facing when the host was detected', () => {
    const { context, warnings } = ContextLoader.forReport(tmpDir(), detected);
    expect(context?.config.exposure).toBe('internet-facing');
    expect(context?.sourceFile).toBe('hawkeye expose');
    expect(warnings).toEqual([]);
  });

  it('never lowers the exposure: a host that did not answer keeps the declared value', () => {
    const dir = tmpDir({ '.hawkeye.yaml': 'exposure: internet-facing\n' });
    const { context } = ContextLoader.forReport(dir, { ...detected, is_internet_facing: false });
    expect(context?.config.exposure).toBe('internet-facing');

    const unknown = ContextLoader.forReport(tmpDir(), { ...detected, is_internet_facing: false });
    expect(unknown.context).toBeNull();
  });

  it('warns and uses internet-facing when the declared exposure contradicts the detection', () => {
    const dir = tmpDir({ '.hawkeye.yaml': 'application_name: api\nexposure: internal-only\n' });
    const { context, warnings } = ContextLoader.forReport(dir, detected);
    expect(context?.config).toMatchObject({ application_name: 'api', exposure: 'internet-facing' });
    expect(warnings).toEqual([
      '.hawkeye.yaml declares exposure "internal-only", but hawkeye expose found the host reachable from the internet; using internet-facing.',
    ]);
  });

  it('rejects a file that is not an expose result', () => {
    const dir = tmpDir({ 'bad.json': '{"exposure": "internet-facing"}' });
    expect(() => ContextLoader.readExposureFile(path.join(dir, 'bad.json'))).toThrow(/not a hawkeye expose result/);
  });

  it('report --exposure attaches the detection and uses it in HTML, DOCX and JSON', async () => {
    const dir = tmpDir({ 'exposure.json': JSON.stringify(detected) });
    process.chdir(dir); // no .hawkeye.yaml here
    const exposure = path.join(dir, 'exposure.json');

    const html = (await runReportPipeline({ input: SAMPLE, format: 'html', exposure })) as string;
    expect(html).toContain('exposure-internet-facing');
    expect(html).toContain('detected by hawkeye expose via DNS, SSL');
    expect(html).toMatch(/Risk scores adjusted by <strong>↑ Increased 50%<\/strong>/);

    const json = JSON.parse((await runReportPipeline({ input: SAMPLE, format: 'json', exposure })) as string);
    expect(json.context.exposure).toEqual(detected);

    const docx = (await runReportPipeline({ input: SAMPLE, format: 'docx', exposure })) as Buffer;
    const xml = await (await JSZip.loadAsync(docx)).file('word/document.xml')!.async('string');
    const text = xml.replace(/<[^>]+>/g, ' ');
    expect(text).toContain('Análise de Exposição à Internet (hawkeye expose)');
    expect(text).toContain('203.0.113.10');
  });
});
