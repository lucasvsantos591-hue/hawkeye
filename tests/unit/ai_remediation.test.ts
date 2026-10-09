import { describe, it, expect } from 'vitest';
import { buildRemediationPrompt, parseRemediationResponse } from '../../src/adapters/ai_providers/prompts';
import { enrichRemediations } from '../../src/adapters/ai_providers/enrich';
import type { AIProvider, RemediationSuggestion } from '../../src/adapters/ai_providers/ai_provider.interface';
import type { VulnerabilityFinding } from '../../src/types/analysis-result';

/** A finding shaped like the engine's output: remediation from the advisory, no AI fields. */
function finding(pkg: string, cve: string, ecosystem = 'PyPI'): VulnerabilityFinding {
  return {
    vulnerability: {
      cve_id: cve,
      advisory_id: `GHSA-${pkg}`,
      summary: `Issue in ${pkg}`,
      ecosystem,
      package: pkg,
      current_version: '1.0.0',
      affected_versions: ['>=1.0.0 <1.2.0'],
      fixed_version: '1.2.0',
      severity: 'HIGH',
      dependency_type: 'direct',
      introduced_via: [],
    },
    is_reachable: true,
    reachability_level: 2,
    confidence: 80,
    evidence: { files: ['app.py'], members: ['get'], sites: ['app.py:1'] },
    remediation: {
      type: 'MINOR',
      description: `Upgrade ${pkg} from 1.0.0 to 1.2.0 or later.`,
      required_version: '>=1.2.0',
      breaking_changes: false,
      action: `uv add "${pkg}>=1.2.0"`,
    },
  } as VulnerabilityFinding;
}

const ENGINE_FIELDS = ['type', 'description', 'required_version', 'breaking_changes', 'action'] as const;

describe('AI prompt', () => {
  it('gives each finding its own id and passes the engine fix as a fact', () => {
    const prompt = buildRemediationPrompt([finding('requests', 'CVE-1'), finding('urllib3', 'CVE-1')]);
    expect(prompt).toContain('"id":"F1"');
    expect(prompt).toContain('"id":"F2"');
    expect(prompt).toContain('"fixed_version":"1.2.0"');
    expect(prompt).toContain('uv add \\"requests>=1.2.0\\"');
    expect(prompt).toContain('do not change the target version or the command');
  });
});

describe('parseRemediationResponse', () => {
  const findings = [finding('requests', 'CVE-1'), finding('urllib3', 'CVE-2')];

  it('reads an array wrapped in prose or code fences', () => {
    const raw = 'Here you go:\n```json\n[{"id":"F2","effort_estimate":"1 hour"}]\n```\nDone.';
    expect(parseRemediationResponse(raw, findings)).toEqual([{ id: 'F2', effort_estimate: '1 hour' }]);
  });

  it('keeps only well-formed entries for known ids and never invents the missing ones', () => {
    const raw = JSON.stringify([
      { id: 'F1', changes_needed: ['Use Session()', 42, ''], notes: '  check timeouts  ', type: 'MAJOR', action: 'rm -rf /' },
      { id: 'F9', notes: 'unknown id' },
      { id: 'F1', notes: 'duplicate' },
      'garbage',
    ]);
    expect(parseRemediationResponse(raw, findings)).toEqual([
      { id: 'F1', changes_needed: ['Use Session()'], notes: 'check timeouts' },
    ]);
  });

  it('caps the length of what the model writes', () => {
    const raw = JSON.stringify([{ id: 'F1', changes_needed: Array(20).fill('x'.repeat(500)), notes: 'n'.repeat(5000) }]);
    const [s] = parseRemediationResponse(raw, findings);
    expect(s.changes_needed).toHaveLength(8);
    expect(s.changes_needed![0]).toHaveLength(300);
    expect(s.notes).toHaveLength(1000);
  });

  it('throws on an answer without a JSON array (e.g. truncated output)', () => {
    expect(() => parseRemediationResponse('Sorry, I cannot help', findings)).toThrow(/no JSON array/);
    expect(() => parseRemediationResponse('[{"id":"F1","notes":"cut', findings)).toThrow(/no JSON array|not valid JSON/);
  });
});

describe('enrichRemediations', () => {
  class Provider implements AIProvider {
    readonly name = 'fake';
    calls: number[] = [];
    constructor(private answer: (batch: VulnerabilityFinding[], call: number) => RemediationSuggestion[]) {}
    async generateRemediations(batch: VulnerabilityFinding[]) {
      this.calls.push(batch.length);
      return this.answer(batch, this.calls.length);
    }
  }

  it('adds code changes, effort and notes without touching the engine fields', async () => {
    const findings = [finding('requests', 'CVE-1')];
    const before = structuredClone(findings[0].remediation);
    const provider = new Provider(() => [
      { id: 'F1', changes_needed: ['Pass timeout='], effort_estimate: '30 minutes', notes: 'Drops Python 3.7' },
    ]);

    const summary = await enrichRemediations(findings, provider);

    expect(summary).toMatchObject({ enriched: 1, batches: 1, failedBatches: 0 });
    for (const field of ENGINE_FIELDS) expect(findings[0].remediation[field]).toEqual(before[field]);
    expect(findings[0].remediation).toMatchObject({
      changes_needed: ['Pass timeout='],
      effort_estimate: '30 minutes',
      notes: 'Drops Python 3.7',
      ai_provider: 'fake',
    });
  });

  it('never overwrites a field that already has a value', async () => {
    const [f] = [finding('requests', 'CVE-1')];
    f.remediation.effort_estimate = '5 minutes';
    const provider = new Provider(() => [{ id: 'F1', effort_estimate: '3 days' }]);

    const summary = await enrichRemediations([f], provider);

    expect(f.remediation.effort_estimate).toBe('5 minutes');
    expect(f.remediation.ai_provider).toBeUndefined();
    expect(summary.enriched).toBe(0);
  });

  it('enriches each finding of a CVE that appears in several packages, and advisories without a CVE', async () => {
    const findings = [finding('requests', 'CVE-1'), finding('requests', 'CVE-1', 'npm'), finding('jinja2', '')];
    const provider = new Provider(batch => batch.map((f, i) => ({ id: `F${i + 1}`, notes: `about ${f.vulnerability.ecosystem}` })));

    await enrichRemediations(findings, provider);

    expect(findings.map(f => f.remediation.notes)).toEqual(['about PyPI', 'about npm', 'about PyPI']);
  });

  it('sends findings in batches, and a failed batch only loses its own suggestions', async () => {
    const findings = Array.from({ length: 45 }, (_, i) => finding(`pkg${i}`, `CVE-${i}`));
    const provider = new Provider((batch, call) => {
      if (call === 2) throw new Error('max_tokens reached');
      return batch.map((_, i) => ({ id: `F${i + 1}`, effort_estimate: `call ${call}` }));
    });

    const summary = await enrichRemediations(findings, provider);

    expect(provider.calls).toEqual([20, 20, 5]);
    expect(summary).toMatchObject({ batches: 3, failedBatches: 1, enriched: 25 });
    expect(summary.warnings).toEqual(['AI suggestions for findings 21-40 failed: max_tokens reached']);
    expect(findings[0].remediation.effort_estimate).toBe('call 1');
    expect(findings[20].remediation.effort_estimate).toBeUndefined();
    expect(findings[20].remediation.action).toBe('uv add "pkg20>=1.2.0"');
    expect(findings[44].remediation.effort_estimate).toBe('call 3');
  });
});
