import { describe, it, expect, beforeEach } from 'vitest';
import { runReportPipeline, type ReportPipelineOptions, type ReportPipelineDeps } from '../../src/cli/commands/report';
import type { VulnerabilityFinding } from '../../src/types/analysis-result';
import type { AIProvider, RemediationSuggestion } from '../../src/adapters/ai_providers/ai_provider.interface';
import * as fs from 'fs';
import * as path from 'path';

class FakeAIProvider implements AIProvider {
  readonly name = 'fake';

  async generateRemediations(findings: VulnerabilityFinding[]): Promise<RemediationSuggestion[]> {
    return findings.map((f) => ({
      cve_id: f.vulnerability.cve_id,
      type: 'MINOR' as const,
      description: `AI suggestion for ${f.vulnerability.package}`,
      action: `npm install ${f.vulnerability.package}@latest`,
    }));
  }
}

describe('report', () => {
  const fixtureDir = path.join(process.cwd(), 'tests/fixtures/analysis-results');
  const sampleJsonPath = path.join(fixtureDir, 'sample-basic.json');

  beforeEach(() => {
    // Verify fixture exists
    expect(fs.existsSync(sampleJsonPath)).toBe(true);
  });

  describe('runReportPipeline', () => {
    it('should generate HTML report without AI', async () => {
      const opts: ReportPipelineOptions = {
        input: sampleJsonPath,
        format: 'html',
        aiProvider: 'none',
      };

      const html = await runReportPipeline(opts);

      expect(html).toContain('Hawkeye Vulnerability Report');
      expect(html).toContain('CVE-2023-12345');
      expect(html).toContain('CVE-2023-54321');
      expect(html).toContain('express@4.16.0');
      expect(html).not.toContain('Powered by');
    });

    it('should generate Markdown report without AI', async () => {
      const opts: ReportPipelineOptions = {
        input: sampleJsonPath,
        format: 'markdown',
        aiProvider: 'none',
      };

      const md = await runReportPipeline(opts);

      expect(md).toContain('# VRA - Vulnerability Reachability Analysis Report');
      expect(md).toContain('CVE-2023-12345');
      expect(md).toContain('CVE-2023-54321');
      expect(md).toContain('express@4.16.0');
      expect(md).not.toContain('Powered by');
    });

    it('should generate JSON report without AI', async () => {
      const opts: ReportPipelineOptions = {
        input: sampleJsonPath,
        format: 'json',
        aiProvider: 'none',
      };

      const json = await runReportPipeline(opts);
      const parsed = JSON.parse(json);

      expect(parsed.project_name).toBe('sample-app');
      expect(parsed.results).toHaveLength(3);
      expect(parsed.results[0].vulnerability.cve_id).toBe('CVE-2023-12345');
    });

    it('should merge AI suggestions into HTML report', async () => {
      const fakeProvider = new FakeAIProvider();
      const opts: ReportPipelineOptions = {
        input: sampleJsonPath,
        format: 'html',
        aiProvider: 'fake',
      };

      const deps: ReportPipelineDeps = {
        createProvider: () => fakeProvider,
      };

      const html = await runReportPipeline(opts, deps);

      expect(html).toContain('Powered by fake');
      expect(html).toContain('AI suggestion for express');
      expect(html).toContain('npm install express@latest');
    });

    it('should merge AI suggestions by cve_id correctly', async () => {
      const fakeProvider = new FakeAIProvider();
      const opts: ReportPipelineOptions = {
        input: sampleJsonPath,
        format: 'json',
        aiProvider: 'fake',
      };

      const deps: ReportPipelineDeps = {
        createProvider: () => fakeProvider,
      };

      const json = await runReportPipeline(opts, deps);
      const result = JSON.parse(json);

      expect(result.results[0].remediation.description).toBe('AI suggestion for express');
      expect(result.results[1].remediation.description).toBe('AI suggestion for lodash');
    });

    it('should handle invalid JSON input', async () => {
      const badJsonPath = path.join(fixtureDir, 'bad.json');
      fs.writeFileSync(badJsonPath, 'not valid json');

      const opts: ReportPipelineOptions = {
        input: badJsonPath,
        format: 'html',
        aiProvider: 'none',
      };

      try {
        await runReportPipeline(opts);
        expect.fail('Should have thrown error');
      } catch (error) {
        expect((error as Error).message).toContain('Invalid analysis result JSON');
      } finally {
        fs.unlinkSync(badJsonPath);
      }
    });

    it('should handle malformed analysis result', async () => {
      const badResultPath = path.join(fixtureDir, 'bad-result.json');
      fs.writeFileSync(badResultPath, JSON.stringify({ project_name: 'test' }));

      const opts: ReportPipelineOptions = {
        input: badResultPath,
        format: 'html',
        aiProvider: 'none',
      };

      try {
        await runReportPipeline(opts);
        expect.fail('Should have thrown error');
      } catch (error) {
        expect((error as Error).message).toContain('Invalid analysis result JSON');
      } finally {
        fs.unlinkSync(badResultPath);
      }
    });

    it('should handle missing input file', async () => {
      const opts: ReportPipelineOptions = {
        input: path.join(fixtureDir, 'nonexistent.json'),
        format: 'html',
        aiProvider: 'none',
      };

      try {
        await runReportPipeline(opts);
        expect.fail('Should have thrown error');
      } catch (error) {
        expect((error as Error).message).toContain('ENOENT');
      }
    });

    it('should gracefully handle AI provider errors', async () => {
      const errorProvider: AIProvider = {
        name: 'error',
        async generateRemediations() {
          throw new Error('AI service unavailable');
        },
      };

      const opts: ReportPipelineOptions = {
        input: sampleJsonPath,
        format: 'html',
        aiProvider: 'error',
      };

      const deps: ReportPipelineDeps = {
        createProvider: () => errorProvider,
      };

      // Should not throw - should continue without AI
      const html = await runReportPipeline(opts, deps);
      expect(html).toContain('Hawkeye Vulnerability Report');
    });

    it('should preserve remediation fields when not using AI', async () => {
      const opts: ReportPipelineOptions = {
        input: sampleJsonPath,
        format: 'json',
        aiProvider: 'none',
      };

      const json = await runReportPipeline(opts);
      const result = JSON.parse(json);

      // First finding has MINOR remediation from fixture
      expect(result.results[0].remediation.type).toBe('MINOR');
      expect(result.results[0].remediation.action).toBe('npm install express@4.17.1');

      // Second has MAJOR
      expect(result.results[1].remediation.type).toBe('MAJOR');
      expect(result.results[1].remediation.effort_estimate).toBe('2-4 hours');

      // Third is OPTIONAL
      expect(result.results[2].remediation.type).toBe('OPTIONAL');
    });
  });
});
