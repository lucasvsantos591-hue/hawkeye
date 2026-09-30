import type { ExposureContext } from '../../types/context.js';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface RescoredFinding {
  cve_id: string;
  original_severity: SeverityLevel;
  adjusted_severity: SeverityLevel;
  exposure_adjustment: boolean;
  mitigation_reason?: string;
}

export class ExposureRescoring {
  resolveFinding(
    cve: any,
    exposure: ExposureContext | undefined,
  ): RescoredFinding {
    const original_severity = this.cveSeverityToLevel(cve.severity);
    let adjusted_severity = original_severity;
    let exposure_adjustment = false;
    let mitigation_reason: string | undefined;

    // If application is NOT internet-facing, reduce severity
    if (exposure?.is_internet_facing === false) {
      exposure_adjustment = true;
      adjusted_severity = this.decreaseSeverity(original_severity);
      mitigation_reason = `Application is not internet-facing. Reduced from ${original_severity} to ${adjusted_severity}.`;
    }

    // If application IS internet-facing and behind strong mitigations
    if (exposure?.is_internet_facing === true) {
      // Check for strong protective measures
      const hasSSLCert = !!exposure.ssl_certificate;
      const cdnBehind = exposure.cdn_info?.provider;

      if (hasSSLCert && cdnBehind) {
        adjusted_severity = this.decreaseSeverity(original_severity);
        exposure_adjustment = true;
        mitigation_reason = `Application is behind ${cdnBehind} CDN with valid SSL certificate, providing additional protection.`;
      }
    }

    return {
      cve_id: cve.cve_id,
      original_severity,
      adjusted_severity,
      exposure_adjustment,
      mitigation_reason,
    };
  }

  private cveSeverityToLevel(severity: string): SeverityLevel {
    const normalized = (severity || '').toUpperCase();
    if (normalized.includes('CRITICAL')) return 'CRITICAL';
    if (normalized.includes('HIGH')) return 'HIGH';
    if (normalized.includes('MEDIUM')) return 'MEDIUM';
    return 'LOW';
  }

  private decreaseSeverity(level: SeverityLevel): SeverityLevel {
    const severityOrder: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const currentIndex = severityOrder.indexOf(level);

    if (currentIndex === -1 || currentIndex >= severityOrder.length - 1) {
      return 'LOW';
    }

    return severityOrder[currentIndex + 1];
  }
}
