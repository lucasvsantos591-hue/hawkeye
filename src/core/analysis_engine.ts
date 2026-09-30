import { ManifestReader, ProjectManifest } from './manifest_reader.js';
import { VulnerabilityMatcher, VulnerabilityMatch, CVE } from './vuln_matcher.js';
import { ReachabilityAnalyzer } from './reachability.js';
import {
  VulnerabilityFinding,
  AnalysisResult,
} from '../types/analysis-result.js';
import * as path from 'path';

export interface AnalysisEngineOptions {
  projectPath: string;
  level?: 1 | 2 | 3;
  language?: string;
}

export class AnalysisEngine {
  private options: Required<AnalysisEngineOptions>;
  private manifest!: ProjectManifest;
  private vulnMatcher: VulnerabilityMatcher;
  private reachabilityAnalyzer!: ReachabilityAnalyzer;

  constructor(options: AnalysisEngineOptions) {
    this.options = {
      projectPath: options.projectPath,
      level: options.level || 2,
      language: options.language || 'javascript',
    };

    this.vulnMatcher = new VulnerabilityMatcher();
  }

  /**
   * Run the complete analysis pipeline
   */
  async analyze(): Promise<AnalysisResult> {
    try {
      // Step 1: Read project manifest
      this.manifest = ManifestReader.readProjectManifest(this.options.projectPath);

      // Step 2: Load CVE database (for now, using mock data)
      this.loadMockCveDatabase();

      // Step 3: Match dependencies against CVEs
      const vulnMatches = this.vulnMatcher.matchDependencies(this.manifest.dependencies);

      // Step 4: Analyze reachability based on level
      this.reachabilityAnalyzer = new ReachabilityAnalyzer(this.options.projectPath);
      const findings = await this.analyzeReachability(vulnMatches);

      // Step 5: Build analysis result
      return this.buildAnalysisResult(findings);
    } catch (error) {
      throw new Error(`Analysis failed: ${(error as Error).message}`);
    }
  }

  /**
   * Analyze reachability for vulnerable dependencies
   */
  private async analyzeReachability(matches: VulnerabilityMatch[]): Promise<VulnerabilityFinding[]> {
    const findings: VulnerabilityFinding[] = [];

    for (const match of matches) {
      if (!match.hasVulnerabilities) {
        continue;
      }

      for (const cve of match.vulnerabilities) {
        let isReachable = false;
        let reachabilityLevel: 1 | 2 | 3 = 1;
        let callChain: VulnerabilityFinding['call_chain'];

        // Level 1: Check if package is imported
        if (this.options.level >= 1) {
          const level1 = await this.reachabilityAnalyzer.analyzeLevel1(cve.package_name);
          isReachable = level1.level1IsReachable;
          reachabilityLevel = 1;

          if (isReachable && level1.importPaths.length > 0) {
            callChain = {
              entry_point: 'src/index.ts',
              path: level1.importPaths,
            };
          }
        }

        // Level 2: Check if vulnerable function is called
        if (this.options.level >= 2 && isReachable) {
          const level2 = await this.reachabilityAnalyzer.analyzeLevel2(
            cve.package_name,
            'vulnerableFunction',
            'src/index.ts',
          );
          isReachable = level2.level2IsReachable;
          reachabilityLevel = 2;

          if (level2.callChain) {
            callChain = {
              entry_point: 'src/index.ts',
              path: level2.callChain,
            };
          }
        }

        // Create finding
        findings.push({
          vulnerability: {
            cve_id: cve.cve_id,
            package: cve.package_name,
            current_version: match.dependency.version,
            affected_versions: cve.affected_versions,
            severity: cve.severity,
          },
          is_reachable: isReachable,
          reachability_level: reachabilityLevel,
          confidence: isReachable ? 75 : 100,
          call_chain: callChain,
          reason: !isReachable ? 'Package imported but vulnerable function not called' : undefined,
          remediation: {
            type: 'MINOR',
            description: `Update ${cve.package_name} to a patched version`,
            required_version: '>=1.0.0', // Should come from CVE data
            breaking_changes: false,
            action: `npm install ${cve.package_name}@latest`,
          },
        });
      }
    }

    return findings;
  }

  /**
   * Build final analysis result
   */
  private buildAnalysisResult(findings: VulnerabilityFinding[]): AnalysisResult {
    const reachableFindings = findings.filter(f => f.is_reachable);

    return {
      schema_version: '1.0.0',
      generated_at: new Date().toISOString(),
      project_name: path.basename(this.options.projectPath),
      project_path: this.options.projectPath,
      total_vulnerabilities: findings.length,
      reachable_vulnerabilities: reachableFindings.length,
      overall_risk_score: this.calculateRiskScore(reachableFindings),
      summary: {
        critical_reachable: reachableFindings.filter(f => f.vulnerability.severity === 'CRITICAL').length,
        high_reachable: reachableFindings.filter(f => f.vulnerability.severity === 'HIGH').length,
        medium_reachable: reachableFindings.filter(f => f.vulnerability.severity === 'MEDIUM').length,
        false_positives_filtered: findings.length - reachableFindings.length,
      },
      results: findings,
    };
  }

  /**
   * Calculate overall risk score based on findings
   */
  private calculateRiskScore(findings: VulnerabilityFinding[]): number {
    if (findings.length === 0) {
      return 0;
    }

    const severityScores: Record<string, number> = {
      CRITICAL: 100,
      HIGH: 75,
      MEDIUM: 50,
      LOW: 25,
    };

    const totalScore = findings.reduce((sum, finding) => {
      const severityScore = severityScores[finding.vulnerability.severity] || 0;
      const confidenceMultiplier = finding.confidence / 100;
      return sum + (severityScore * confidenceMultiplier);
    }, 0);

    return Math.min(100, Math.round(totalScore / findings.length));
  }

  /**
   * Load mock CVE database (for now)
   * In production, this would fetch from NVD API or cache
   */
  private loadMockCveDatabase(): void {
    const mockCves: CVE[] = [
      {
        cve_id: 'CVE-2023-12345',
        package_name: 'axios',
        affected_versions: ['<1.4.0'],
        severity: 'HIGH',
        description: 'Prototype pollution vulnerability in axios',
      },
      {
        cve_id: 'CVE-2023-54321',
        package_name: 'lodash',
        affected_versions: ['<4.17.21'],
        severity: 'CRITICAL',
        description: 'Arbitrary code execution in lodash',
      },
      {
        cve_id: 'CVE-2022-99999',
        package_name: 'express',
        affected_versions: ['<4.18.0'],
        severity: 'MEDIUM',
        description: 'DoS vulnerability in express',
      },
    ];

    this.vulnMatcher.setCveDatabase(mockCves);
  }
}
