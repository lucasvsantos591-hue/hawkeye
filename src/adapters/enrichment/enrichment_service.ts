import type { VulnerabilityFinding } from '../../types/analysis-result.js';
import type { CVEEnrichment, EnrichedVulnerabilityFinding } from '../../types/cve-enrichment.js';
import type { ExposureContext } from '../../types/context.js';
import { cisaKEVAdapter } from './cisa_kev_adapter.js';
import { epssAdapter } from './epss_adapter.js';
import { ExposureRescoring } from './exposure_rescoring.js';

/**
 * CVE Enrichment Service
 * Combines multiple public APIs to provide full context:
 * - CISA KEV: Known exploited vulnerabilities
 * - FIRST EPSS: Exploit prediction scoring
 */

class EnrichmentService {
  private exposureRescoring: ExposureRescoring;

  constructor() {
    this.exposureRescoring = new ExposureRescoring();
  }

  /**
   * Calculate priority score (0-100) based on enrichment and reachability
   */
  private calculatePriorityScore(
    enrichment: CVEEnrichment,
    isReachable: boolean,
    confidence: number,
  ): number {
    let score = 0;

    // EPSS score (0-100) has 40% weight
    if (enrichment.epss) {
      score += enrichment.epss.score * 0.4;
    }

    // Known exploitation (CISA KEV) has 30% weight
    if (enrichment.cisa_kev?.is_known_exploited) {
      score += 30;
    }

    // Reachability has 30% weight
    if (isReachable) {
      score += confidence * 0.3; // Multiply by confidence (0-1)
    }

    return Math.min(100, Math.round(score));
  }

  /**
   * Map priority score to priority level
   */
  private getPriorityLevel(score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  }

  /**
   * Generate human-readable priority reasoning
   */
  private getPriorityReasoning(
    enrichment: CVEEnrichment,
    isReachable: boolean,
    confidence: number,
  ): string {
    const reasons: string[] = [];

    if (enrichment.epss && enrichment.epss.score >= 7) {
      reasons.push(`High EPSS score (${enrichment.epss.score})`);
    }

    if (enrichment.cisa_kev?.is_known_exploited) {
      reasons.push('Being exploited in the wild (CISA KEV)');
    }

    if (enrichment.cisa_kev?.is_ransomware) {
      reasons.push('Used in ransomware campaigns');
    }

    if (isReachable) {
      reasons.push(`Reachable in your code (${confidence}% confidence)`);
    } else {
      reasons.push('Not reachable in your code');
    }

    return reasons.join(' + ');
  }

  /**
   * Enrich a single vulnerability with all available data
   */
  async enrichVulnerability(
    finding: VulnerabilityFinding,
    exposure?: ExposureContext,
  ): Promise<EnrichedVulnerabilityFinding> {
    const cveId = finding.vulnerability.cve_id;

    // Fetch enrichment data in parallel
    const [cisaData, epssData] = await Promise.all([
      cisaKEVAdapter.enrichCVE(cveId),
      epssAdapter.enrichCVE(cveId),
    ]);

    const enrichment: CVEEnrichment = {
      cve_id: cveId,
      cisa_kev: cisaData as any,
      epss: epssData as any,
    };

    // Apply exposure-based rescoring if available
    let adjustedSeverity = finding.vulnerability.severity;
    let exposureRescoring = null;

    if (exposure) {
      const rescored = this.exposureRescoring.resolveFinding(
        finding.vulnerability,
        exposure,
      );
      adjustedSeverity = rescored.adjusted_severity;
      exposureRescoring = rescored;
    }

    // Calculate priority
    const priorityScore = this.calculatePriorityScore(
      enrichment,
      finding.is_reachable,
      finding.confidence / 100, // Convert 0-100 to 0-1
    );

    const priority = this.getPriorityLevel(priorityScore);
    let priorityReasoning = this.getPriorityReasoning(
      enrichment,
      finding.is_reachable,
      finding.confidence,
    );

    // Add exposure-based reasoning if applicable
    if (exposureRescoring?.mitigation_reason) {
      priorityReasoning += ` + ${exposureRescoring.mitigation_reason}`;
    }

    return {
      cve_id: cveId,
      package: finding.vulnerability.package,
      current_version: finding.vulnerability.current_version,
      affected_versions: finding.vulnerability.affected_versions,
      severity: adjustedSeverity as any,
      enrichment,
      is_reachable: finding.is_reachable,
      reachability_level: finding.reachability_level,
      confidence: finding.confidence,
      priority,
      priority_score: priorityScore,
      priority_reasoning: priorityReasoning,
    };
  }

  /**
   * Enrich multiple vulnerabilities
   */
  async enrichVulnerabilities(
    findings: VulnerabilityFinding[],
    exposure?: ExposureContext,
  ): Promise<EnrichedVulnerabilityFinding[]> {
    return Promise.all(findings.map((f) => this.enrichVulnerability(f, exposure)));
  }

  /**
   * Clear all caches
   */
  clearCaches() {
    cisaKEVAdapter.clearCache();
    epssAdapter.clearCache();
  }
}

export const enrichmentService = new EnrichmentService();
