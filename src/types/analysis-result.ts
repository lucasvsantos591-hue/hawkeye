export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type RemediationType = 'MAJOR' | 'MINOR' | 'OPTIONAL';

export interface VulnerabilityInfo {
  cve_id: string;
  package: string;
  current_version: string;
  affected_versions: string[];
  severity: Severity;
  epss_score?: number;
  is_exploited_in_wild?: boolean;
}

export interface CallChain {
  entry_point: string;
  path: string[];
  taint_analysis?: string;
}

export interface Remediation {
  type: RemediationType;
  description: string;
  required_version?: string;
  breaking_changes?: boolean;
  changes_needed?: string[];
  action?: string;
  effort_estimate?: string;
  notes?: string;
}

export interface VulnerabilityFinding {
  vulnerability: VulnerabilityInfo;
  is_reachable: boolean;
  reachability_level: 1 | 2 | 3;
  confidence: number;
  call_chain?: CallChain;
  reason?: string;
  remediation: Remediation;
}

export interface AnalysisSummary {
  critical_reachable: number;
  high_reachable: number;
  medium_reachable: number;
  false_positives_filtered: number;
}

export interface AnalysisResult {
  schema_version: string;
  generated_at: string;
  project_name: string;
  project_path?: string;
  total_vulnerabilities: number;
  reachable_vulnerabilities: number;
  overall_risk_score: number;
  summary?: AnalysisSummary;
  results: VulnerabilityFinding[];
  context?: any;
}

export function assertAnalysisResult(data: unknown): AnalysisResult {
  if (typeof data !== 'object' || data === null) {
    throw new Error('Analysis result must be an object');
  }

  const obj = data as Record<string, unknown>;

  if (
    typeof obj.schema_version !== 'string' ||
    typeof obj.generated_at !== 'string' ||
    typeof obj.project_name !== 'string' ||
    typeof obj.total_vulnerabilities !== 'number' ||
    typeof obj.reachable_vulnerabilities !== 'number' ||
    typeof obj.overall_risk_score !== 'number' ||
    !Array.isArray(obj.results)
  ) {
    throw new Error('Invalid analysis result structure: missing or wrong type for required fields');
  }

  obj.results.forEach((result: unknown, index: number) => {
    if (typeof result !== 'object' || result === null) {
      throw new Error(`results[${index}] must be an object`);
    }

    const r = result as Record<string, unknown>;
    if (
      typeof r.is_reachable !== 'boolean' ||
      typeof r.reachability_level !== 'number' ||
      typeof r.confidence !== 'number' ||
      !r.vulnerability ||
      !r.remediation
    ) {
      throw new Error(`results[${index}] missing or has wrong type for required fields`);
    }

    const vuln = r.vulnerability as Record<string, unknown>;
    if (typeof vuln.cve_id !== 'string' || typeof vuln.package !== 'string') {
      throw new Error(`results[${index}].vulnerability missing cve_id or package`);
    }

    const rem = r.remediation as Record<string, unknown>;
    if (typeof rem.type !== 'string' || typeof rem.description !== 'string') {
      throw new Error(`results[${index}].remediation missing type or description`);
    }
  });

  return obj as unknown as AnalysisResult;
}
