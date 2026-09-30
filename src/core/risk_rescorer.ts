import { VulnerabilityFinding } from '../types/analysis-result.js';
import { HawkeyeContext } from '../adapters/context/context_loader.js';
import { ContextLoader } from '../adapters/context/context_loader.js';

export interface RescoreResult {
  originalScore: number;
  adjustedScore: number;
  multiplier: number;
  reason: string;
  exposure: string;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export function findingKey(finding: VulnerabilityFinding): string {
  const v = finding.vulnerability;
  return `${v.advisory_id ?? v.cve_id}:${v.package}@${v.current_version}`;
}

/**
 * Rescores vulnerabilities based on network exposure and context
 * Internet-facing applications have higher risk multipliers
 */
export class RiskRescorer {
  private context: HawkeyeContext | null;

  constructor(context?: HawkeyeContext | null) {
    this.context = context || null;
  }

  /**
   * Rescore a single finding
   */
  rescore(finding: VulnerabilityFinding): RescoreResult {
    const originalScore = this.calculateOriginalScore(finding);
    const exposure = ContextLoader.getExposure(this.context);
    const multiplier = this.getMultiplier(exposure);

    const adjustedScore = Math.min(100, Math.round(originalScore * multiplier));
    const riskLevel = this.getRiskLevel(adjustedScore);

    return {
      originalScore,
      adjustedScore,
      multiplier,
      reason: this.getRescoreReason(exposure, multiplier),
      exposure,
      riskLevel,
    };
  }

  /**
   * Rescore all findings
   */
  rescoreFindings(findings: VulnerabilityFinding[]): Map<string, RescoreResult> {
    const results = new Map<string, RescoreResult>();

    for (const finding of findings) {
      results.set(findingKey(finding), this.rescore(finding));
    }

    return results;
  }

  /**
   * Calculate original risk score for a finding
   */
  private calculateOriginalScore(finding: VulnerabilityFinding): number {
    const severityScores: Record<string, number> = {
      CRITICAL: 90,
      HIGH: 75,
      MEDIUM: 50,
      LOW: 25,
    };

    const baseScore = severityScores[finding.vulnerability.severity] || 50;
    const reachabilityBonus = finding.is_reachable ? 10 : 0;
    const epssBonus = finding.vulnerability.epss_score
      ? Math.round((finding.vulnerability.epss_score / 100) * 20)
      : 0;
    const kevBonus = finding.vulnerability.is_exploited_in_wild ? 15 : 0;

    const score = baseScore + reachabilityBonus + epssBonus + kevBonus;
    return Math.min(100, score);
  }

  /**
   * Get multiplier based on network exposure
   */
  private getMultiplier(exposure: string): number {
    switch (exposure) {
      case 'internet-facing':
        // Internet-facing apps have 50% higher risk
        return 1.5;

      case 'internal-only':
        // Internal apps have 20% lower risk
        return 0.8;

      case 'isolated':
        // Isolated apps have 60% lower risk
        return 0.4;

      default:
        // Unknown exposure - assume moderate risk
        return 1.0;
    }
  }

  /**
   * Get risk level from score
   */
  private getRiskLevel(score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Get human-readable reason for rescore
   */
  private getRescoreReason(exposure: string, multiplier: number): string {
    if (multiplier > 1.2) {
      return `Application is ${exposure} - significantly increases vulnerability impact`;
    } else if (multiplier > 1.0) {
      return `Application is ${exposure} - increases vulnerability impact`;
    } else if (multiplier < 0.8) {
      return `Application is ${exposure} - decreases vulnerability impact`;
    } else {
      return `Application exposure: ${exposure}`;
    }
  }

  /**
   * Get exposure level
   */
  getExposure(): string {
    return ContextLoader.getExposure(this.context);
  }

  /**
   * Check if application is internet-facing
   */
  isInternetFacing(): boolean {
    return ContextLoader.isInternetFacing(this.context);
  }

  /**
   * Summary of rescoring impact
   */
  getSummary(findings: VulnerabilityFinding[]): {
    originalCritical: number;
    adjustedCritical: number;
    originalHigh: number;
    adjustedHigh: number;
    averageMultiplier: number;
    exposure: string;
  } {
    const rescores = this.rescoreFindings(findings);

    let originalCritical = 0;
    let adjustedCritical = 0;
    let originalHigh = 0;
    let adjustedHigh = 0;
    let totalMultiplier = 0;

    for (const rescore of rescores.values()) {
      if (rescore.originalScore >= 80) originalCritical++;
      if (rescore.adjustedScore >= 80) adjustedCritical++;
      if (rescore.originalScore >= 60 && rescore.originalScore < 80) originalHigh++;
      if (rescore.adjustedScore >= 60 && rescore.adjustedScore < 80) adjustedHigh++;
      totalMultiplier += rescore.multiplier;
    }

    return {
      originalCritical,
      adjustedCritical,
      originalHigh,
      adjustedHigh,
      averageMultiplier: rescores.size > 0 ? totalMultiplier / rescores.size : 1,
      exposure: this.getExposure(),
    };
  }
}
