import { AnalysisResult, VulnerabilityFinding } from '../../types/analysis-result.js';

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
              version: this.result.schema_version,
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
      const cveId = finding.vulnerability.cve_id;

      if (!ruleMap.has(cveId)) {
        ruleMap.set(cveId, {
          id: cveId,
          shortDescription: {
            text: `Vulnerability in ${finding.vulnerability.package}`,
          },
          fullDescription: {
            text: `CVE: ${cveId}\nPackage: ${finding.vulnerability.package}\nSeverity: ${finding.vulnerability.severity}`,
          },
          help: {
            text: `Update ${finding.vulnerability.package} to a version that includes the fix for ${cveId}`,
          },
          properties: {
            severity: finding.vulnerability.severity,
            cvss_score: finding.vulnerability.epss_score,
            is_exploited_in_wild: finding.vulnerability.is_exploited_in_wild,
          },
        });
      }
    }

    return Array.from(ruleMap.values());
  }

  /**
   * Generate SARIF results from findings
   */
  private generateResults(): any[] {
    return this.result.results.map((finding) => ({
      ruleId: finding.vulnerability.cve_id,
      level: this.getSARIFLevel(finding),
      message: {
        text: `${finding.vulnerability.severity} vulnerability in ${finding.vulnerability.package}@${finding.vulnerability.current_version}`,
      },
      locations: [
        {
          logicalLocations: [
            {
              name: finding.vulnerability.package,
              kind: 'module',
            },
          ],
          message: {
            text: `Reachability Level ${finding.reachability_level}: ${finding.is_reachable ? 'Reachable' : 'Not Reachable'}`,
          },
        },
      ],
      partialFingerprints: {
        vulnerabilityHash: `${finding.vulnerability.cve_id}/${finding.vulnerability.package}`,
      },
      properties: {
        confidence: finding.confidence,
        reachable: finding.is_reachable,
        affected_versions: finding.vulnerability.affected_versions,
        current_version: finding.vulnerability.current_version,
        remediation_type: finding.remediation.type,
        remediation_action: finding.remediation.action,
      },
    }));
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
