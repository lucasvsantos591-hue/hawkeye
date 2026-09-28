import type { VulnerabilityFinding } from '../../types/analysis-result.js';
import type { RemediationSuggestion } from './ai_provider.interface.js';

export function buildRemediationPrompt(findings: VulnerabilityFinding[]): string {
  const findingsJson = findings
    .map((f) => ({
      cve_id: f.vulnerability.cve_id,
      package: f.vulnerability.package,
      current_version: f.vulnerability.current_version,
      affected_versions: f.vulnerability.affected_versions,
      severity: f.vulnerability.severity,
      is_reachable: f.is_reachable,
      call_chain: f.call_chain?.path || [],
    }))
    .map((f) => JSON.stringify(f))
    .join('\n');

  return `You are a security expert analyzing vulnerability remediations. For each CVE below, provide remediation advice in JSON format.

For each CVE, generate a JSON object with:
- cve_id (string): The CVE ID
- type (string): "MAJOR" if requires code changes, "MINOR" if only version bump, "OPTIONAL" if not reachable/not actionable
- description (string): Brief, actionable remediation description
- required_version (string, optional): Target package version
- breaking_changes (boolean, optional): Whether upgrade has breaking changes
- changes_needed (array of strings, optional): Specific code changes required
- action (string, optional): The command or action to take
- effort_estimate (string, optional): Time estimate like "5 minutes" or "2-4 hours"
- notes (string, optional): Additional context

Return ONLY a JSON array, like:
[{"cve_id":"CVE-...", "type":"MINOR", ...}, {"cve_id":"CVE-...", "type":"MAJOR", ...}]

Vulnerabilities to remediate:
${findingsJson}

Remember: respond with ONLY valid JSON array, no markdown, no explanations.`;
}

export function parseRemediationResponse(
  raw: string,
  findings: VulnerabilityFinding[],
): RemediationSuggestion[] {
  try {
    let json = raw.trim();

    // Remove markdown code fences if present
    if (json.startsWith('```json')) {
      json = json.slice(7);
    } else if (json.startsWith('```')) {
      json = json.slice(3);
    }

    if (json.endsWith('```')) {
      json = json.slice(0, -3);
    }

    json = json.trim();

    const parsed = JSON.parse(json);

    if (!Array.isArray(parsed)) {
      throw new Error('Response is not an array');
    }

    const suggestions = new Map<string, RemediationSuggestion>();
    const findingsMap = new Map(findings.map((f) => [f.vulnerability.cve_id, f]));

    parsed.forEach((item: unknown) => {
      if (typeof item !== 'object' || item === null) {
        return;
      }

      const obj = item as Record<string, unknown>;
      const cveId = obj.cve_id as string | undefined;

      if (!cveId || typeof cveId !== 'string' || !findingsMap.has(cveId)) {
        return;
      }

      const type = (obj.type as string) || 'MINOR';
      const description = (obj.description as string) || 'Update package';

      suggestions.set(cveId, {
        cve_id: cveId,
        type: (type as any) || 'MINOR',
        description,
        required_version: (obj.required_version as string | undefined) || undefined,
        breaking_changes: (obj.breaking_changes as boolean | undefined) || undefined,
        changes_needed: (Array.isArray(obj.changes_needed) ? obj.changes_needed : undefined) as
          | string[]
          | undefined,
        action: (obj.action as string | undefined) || undefined,
        effort_estimate: (obj.effort_estimate as string | undefined) || undefined,
        notes: (obj.notes as string | undefined) || undefined,
      });
    });

    // Fill in missing CVEs with fallback MINOR remediation
    findings.forEach((f) => {
      if (!suggestions.has(f.vulnerability.cve_id)) {
        suggestions.set(f.vulnerability.cve_id, {
          cve_id: f.vulnerability.cve_id,
          type: 'MINOR',
          description: `Update ${f.vulnerability.package} to ≥${f.vulnerability.affected_versions[0]?.replace(/[<>=]/g, '')}`,
          action: `npm install ${f.vulnerability.package}@latest`,
        });
      }
    });

    return Array.from(suggestions.values());
  } catch (error) {
    console.warn(
      `Warning: Failed to parse AI response as JSON. Raw output:\n${raw.slice(0, 200)}...`,
    );

    // Fallback: synthesize MINOR remediations for all findings
    return findings.map((f) => ({
      cve_id: f.vulnerability.cve_id,
      type: 'MINOR' as const,
      description: 'AI response could not be parsed. Manual review recommended.',
      action: 'Manual review required',
      notes: 'Unable to generate AI remediation. See details in log.',
    }));
  }
}
