import type { VulnerabilityFinding, Remediation } from '../../types/analysis-result.js';

export interface RemediationSuggestion extends Remediation {
  cve_id: string;
}

export interface AIProvider {
  readonly name: string;
  generateRemediations(findings: VulnerabilityFinding[]): Promise<RemediationSuggestion[]>;
}
