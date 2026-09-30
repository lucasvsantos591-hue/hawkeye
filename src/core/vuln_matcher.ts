import { PackageDependency } from './manifest_reader';

export interface CVE {
  cve_id: string;
  package_name: string;
  affected_versions: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description?: string;
  published_date?: string;
}

export interface VulnerabilityMatch {
  dependency: PackageDependency;
  vulnerabilities: CVE[];
  hasVulnerabilities: boolean;
}

export class VulnerabilityMatcher {
  private cveDatabase: CVE[] = [];

  /**
   * Initialize with CVE data (from NVD or cache)
   */
  setCveDatabase(cves: CVE[]): void {
    this.cveDatabase = cves;
  }

  /**
   * Match dependencies against CVE database
   */
  matchDependencies(dependencies: PackageDependency[]): VulnerabilityMatch[] {
    return dependencies.map(dep => {
      const vulnerabilities = this.findVulnerabilities(dep);

      return {
        dependency: dep,
        vulnerabilities,
        hasVulnerabilities: vulnerabilities.length > 0,
      };
    });
  }

  /**
   * Find all CVEs affecting a specific dependency version
   */
  private findVulnerabilities(dependency: PackageDependency): CVE[] {
    return this.cveDatabase.filter(cve => {
      if (cve.package_name !== dependency.name) {
        return false;
      }

      // Check if dependency version is in affected_versions
      // For now, simple string comparison. In production, use semver matching
      return cve.affected_versions.some(affectedVer => {
        return this.isVersionAffected(dependency.version, affectedVer);
      });
    });
  }

  /**
   * Check if a version is affected by a CVE pattern
   * Handles patterns like "<1.4.0", ">=1.0.0,<2.0.0", etc.
   */
  private isVersionAffected(currentVersion: string, affectedPattern: string): boolean {
    // Remove 'v' prefix if present
    const cleanCurrent = currentVersion.replace(/^v/, '');
    const cleanPattern = affectedPattern.replace(/^v/, '');

    // Handle specific version match
    if (cleanPattern === cleanCurrent) {
      return true;
    }

    // Handle range patterns (simplified)
    if (cleanPattern.startsWith('<')) {
      const ver = cleanPattern.substring(1);
      return this.compareVersions(cleanCurrent, ver) < 0;
    }

    if (cleanPattern.startsWith('>')) {
      const ver = cleanPattern.substring(1);
      return this.compareVersions(cleanCurrent, ver) > 0;
    }

    if (cleanPattern.startsWith('<=')) {
      const ver = cleanPattern.substring(2);
      return this.compareVersions(cleanCurrent, ver) <= 0;
    }

    if (cleanPattern.startsWith('>=')) {
      const ver = cleanPattern.substring(2);
      return this.compareVersions(cleanCurrent, ver) >= 0;
    }

    return false;
  }

  /**
   * Simple semantic version comparison
   * Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
   */
  private compareVersions(v1: string, v2: string): number {
    const parts1 = v1.split('.').map(p => parseInt(p, 10) || 0);
    const parts2 = v2.split('.').map(p => parseInt(p, 10) || 0);

    const maxLen = Math.max(parts1.length, parts2.length);

    for (let i = 0; i < maxLen; i++) {
      const p1 = parts1[i] || 0;
      const p2 = parts2[i] || 0;

      if (p1 < p2) return -1;
      if (p1 > p2) return 1;
    }

    return 0;
  }
}
