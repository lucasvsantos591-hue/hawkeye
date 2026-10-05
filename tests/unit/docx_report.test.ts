import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import JSZip from 'jszip';
import { renderDocxReport } from '../../src/adapters/report/docx_renderer';
import type { AnalysisResult } from '../../src/types/analysis-result';

async function docxText(buffer: Buffer): Promise<string> {
  const zip = await JSZip.loadAsync(buffer);
  const xml = await zip.file('word/document.xml')!.async('string');
  return xml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
}

describe('DOCX report', () => {
  const sample = JSON.parse(
    fs.readFileSync(path.join(process.cwd(), 'tests/fixtures/analysis-results/sample-basic.json'), 'utf-8'),
  ) as AnalysisResult;

  it('lists the reachable findings in the table of contents, even when an unreachable one comes first', async () => {
    // Unreachable finding first: the TOC used to take the CVE at the same index of the full list.
    const result = { ...sample, results: [sample.results[2], sample.results[0], sample.results[1]] };
    const text = await docxText(await renderDocxReport(result));

    expect(text).toMatch(/3\. CVE-2023-12345 · express/);
    expect(text).toMatch(/4\. CVE-2023-54321/);
    expect(text).not.toMatch(/\d\. CVE-2023-99999 ·/);
  });

  it('describes reachability and priority the way the engine computes them', async () => {
    const text = await docxText(await renderDocxReport(sample));

    expect(text).toContain('Prioridade: alcançável → CISA KEV → severidade → confiança → EPSS');
    expect(text).not.toContain('EPSS 40%');
    expect(text).not.toContain('Taint');
  });

  it('only shows data from the finding, never a canned exploit narrative', async () => {
    const text = await docxText(await renderDocxReport(sample));

    // A fixed lodash prototype-pollution story used to be printed for every finding.
    expect(text).not.toMatch(/__proto__|isAdmin|87% de confiança|Dia 1/);
    for (const finding of sample.results.filter(f => f.is_reachable)) {
      expect(text).toContain(finding.remediation.description);
    }
  });
});
