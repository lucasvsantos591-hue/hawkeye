import type { VulnerabilityFinding } from '../../types/analysis-result.js';

/**
 * What a model adds to a finding's remediation. The version, command and remediation type stay the ones the
 * engine derived from the advisory: a suggestion has no fields for them.
 */
export interface RemediationSuggestion {
  /** Id of the finding in the batch sent to the model ("F1", "F2"...). */
  id: string;
  changes_needed?: string[];
  effort_estimate?: string;
  notes?: string;
}

export interface AIProvider {
  readonly name: string;
  generateRemediations(findings: VulnerabilityFinding[]): Promise<RemediationSuggestion[]>;
}
