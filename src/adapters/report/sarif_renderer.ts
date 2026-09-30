import { AnalysisResult, VulnerabilityFinding } from '../../types/analysis-result.js';

const SECURITY_SEVERITY: Record<string, string> = { CRITICAL: '9.5', HIGH: '8.0', MEDIUM: '5.5', LOW: '3.0' };

function ruleId(finding: VulnerabilityFinding): string {
  return finding.vulnerability.advisory_id ?? finding.vulnerability.cve_id;
}

function locationOf(finding: VulnerabilityFinding): [string, number] {
  const site = finding.evidence?.sites[0];
  const match = site?.match(/^(.*):(\d+)$/);
  return match ? [match[1], Math.max(1, Number(match[2]))] : ['package.json', 1];
}

/**
 * Renders analysis results as SARIF (Static Analysis Results Interchange Format)
 * SARIF is a standard format for static analysis tool results
 */
export class SARIFRenderer {
  private result: AnalysisResult;

  constructor(result: AnalysisResult) {
    this.result = result;
  }

  /**
   * Render as SARIF JSON
   */
  render(): string {
    const sarifResult = {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'Hawkeye',
              version: this.result.scan?.tool_version ?? this.result.schema_version,
              informationUri: 'https://github.com/lucasvsantos591-hue/hawkeye',
              rules: this.generateRules(),
            },
          },
          results: this.generateResults(),
          properties: {
            projectPath: this.result.project_path,
            riskScore: this.result.overall_risk_score,
            generatedAt: this.result.generated_at,
          },
        },
      ],
    };

    return JSON.stringify(sarifResult, null, 2);
  }

  /**
   * Generate SARIF rules from findings
   */
  private generateRules(): any[] {
    const ruleMap = new Map<string, any>();

    for (const finding of this.result.results) {
      const v = finding.vulnerability;
      const id = ruleId(finding);
      if (ruleMap.has(id)) continue;
      ruleMap.set(id, {
        id,
        name: v.cve_id,
        shortDescription: { text: v.summary || `Vulnerability in ${v.package}` },
        fullDescription: {
          text: `${v.cve_id} in ${v.package} (${v.affected_versions.join(', ') || 'see advisory'}). Severity: ${v.severity}.`,
        },
        helpUri: v.advisory_url,
        help: {
          text: v.fixed_version
            ? `Upgrade ${v.package} to ${v.fixed_version} or later.`
            : `No patched version of ${v.package} is published; see the advisory.`,
        },
        properties: {
          tags: ['security', 'dependency'],
          'security-severity': SECURITY_SEVERITY[v.severity] ?? '5.0',
          epss_score: v.epss_score,
          is_exploited_in_wild: v.is_exploited_in_wild,
        },
      });
    }

    return Array.from(ruleMap.values());
  }

  private generateResults(): any[] {
    return this.result.results.map(finding => {
      const v = finding.vulnerability;
      const [file, line] = locationOf(finding);
      return {
        ruleId: ruleId(finding),
        level: this.getSARIFLevel(finding),
        message: {
          text:
            `${v.severity} ${v.cve_id} in ${v.package}@${v.current_version}` +
            `${v.fixed_version ? ` (fixed in ${v.fixed_version})` : ''}. ` +
            `${finding.is_reachable ? 'Reachable' : 'Not reachable'}: ${finding.reason ?? ''}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: file },
              region: { startLine: line },
            },
            logicalLocations: [{ name: v.package, kind: 'module' }],
          },
        ],
        partialFingerprints: {
          vulnerabilityHash: `${ruleId(finding)}/${v.package}@${v.current_version}`,
        },
        properties: {
          confidence: finding.confidence,
          reachable: finding.is_reachable,
          dependency_type: v.dependency_type,
          introduced_via: v.introduced_via,
          affected_versions: v.affected_versions,
          current_version: v.current_version,
          fixed_version: v.fixed_version,
          remediation_action: finding.remediation.action,
        },
      };
    });
  }

  /**
   * Map Hawkeye severity to SARIF level
   */
  private getSARIFLevel(finding: VulnerabilityFinding): string {
    if (!finding.is_reachable) {
      return 'note';
    }

    switch (finding.vulnerability.severity) {
      case 'CRITICAL':
        return 'error';
      case 'HIGH':
        return 'warning';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'note';
      default:
        return 'note';
    }
  }
}
