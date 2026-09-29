import type { HawkeyeContext, ContextualizedFinding, ContextMitigation } from '../../types/context.js';
import type { VulnerabilityFinding } from '../../types/analysis-result.js';

/**
 * Apply infrastructure/network context to reachability findings
 *
 * Rescores CVEs based on real-world mitigations:
 * - WAF rules blocking attack patterns
 * - Authentication gates
 * - Network segmentation
 * - Input validation & sanitization
 */
export class ContextProcessor {
  private context: HawkeyeContext;

  constructor(context: HawkeyeContext) {
    this.context = context;
  }

  /**
   * Process findings and apply context-based adjustments
   */
  async process(findings: VulnerabilityFinding[]): Promise<Map<string, ContextualizedFinding>> {
    const contextualized = new Map<string, ContextualizedFinding>();

    for (const finding of findings) {
      const cveId = finding.vulnerability.cve_id;
      const originalLevel = finding.reachability_level;
      let adjustedLevel = originalLevel;
      const mitigations: ContextMitigation[] = [];

      const entryPoint = finding.call_chain?.entry_point || '';

      // 1. Check WAF rules
      const wafMitigation = this.checkWafRules(entryPoint);
      if (wafMitigation) {
        adjustedLevel = 1;
        mitigations.push(wafMitigation);
      }

      // 2. Check authentication gates
      const authMitigation = this.checkAuthGates(entryPoint);
      if (authMitigation) {
        adjustedLevel = 1;
        mitigations.push(authMitigation);
      }

      // 3. Check network segmentation
      const networkMitigation = this.checkNetworkSegmentation();
      if (networkMitigation) {
        adjustedLevel = 1;
        mitigations.push(networkMitigation);
      }

      // 4. Check input validation
      const validationMitigation = this.checkInputValidation(entryPoint, finding);
      if (validationMitigation) {
        adjustedLevel = 1;
        mitigations.push(validationMitigation);
      }

      contextualized.set(cveId, {
        cve_id: cveId,
        original_reachability_level: originalLevel,
        adjusted_reachability_level: adjustedLevel as 1 | 2 | 3,
        mitigations,
        context_applied: mitigations.length > 0,
      });
    }

    return contextualized;
  }

  /**
   * Check if endpoint is blocked/limited by WAF rules
   */
  private checkWafRules(entryPoint: string): ContextMitigation | null {
    if (!this.context.network?.firewall_rules) {
      return null;
    }

    const rule = this.context.network.firewall_rules.find((r) => this.matchesEndpoint(entryPoint, r.endpoint));

    if (rule?.blocked) {
      return {
        reason: `WAF blocks endpoint: ${rule.reason || 'rule matched'}`,
        severity: 'high',
        evidence: rule.waf || 'WAF rule active',
      };
    }

    if (rule?.rate_limit) {
      return {
        reason: `Rate limiting prevents exploitation: ${rule.rate_limit}`,
        severity: 'medium',
        evidence: `Rate limit: ${rule.rate_limit}`,
      };
    }

    return null;
  }

  /**
   * Check if endpoint requires authentication
   */
  private checkAuthGates(entryPoint: string): ContextMitigation | null {
    if (!this.context.authentication?.gates) {
      return null;
    }

    const gate = this.context.authentication.gates.find((g) => this.matchesEndpoint(entryPoint, g.endpoint));

    if (gate && !gate.bypass) {
      return {
        reason: `Endpoint requires authentication (${gate.gate})`,
        severity: 'high',
        evidence: `Gate: ${gate.gate} — anonymous access blocked`,
      };
    }

    // Check default auth requirement
    if (this.context.authentication.default_requires_auth && !gate?.bypass) {
      return {
        reason: 'Application requires authentication by default',
        severity: 'high',
        evidence: 'default_requires_auth: true',
      };
    }

    return null;
  }

  /**
   * Check if app is network-isolated
   */
  private checkNetworkSegmentation(): ContextMitigation | null {
    const app = this.context.application;

    if (app && app.internet_facing === false) {
      return {
        reason: 'Application is not internet-facing — isolated by network segmentation',
        severity: 'high',
        evidence: 'internet_facing: false',
      };
    }

    if (this.context.network?.vpc_internal) {
      return {
        reason: 'VPC internal-only — not exposed to external networks',
        severity: 'high',
        evidence: 'vpc_internal: true',
      };
    }

    const segmentation = this.context.network?.segmentation;
    if (segmentation?.['database_access'] === 'internal-only') {
      return {
        reason: 'Database is isolated — internal access only',
        severity: 'medium',
        evidence: 'Network segmentation: database_access = internal-only',
      };
    }

    return null;
  }

  /**
   * Check if input validation sanitizes the attack vector
   */
  private checkInputValidation(entryPoint: string, finding: VulnerabilityFinding): ContextMitigation | null {
    if (!this.context.validation?.validators) {
      return null;
    }

    const validator = this.context.validation.validators.find((v) => this.matchesEndpoint(entryPoint, v.endpoint));

    if (!validator) {
      return null;
    }

    if (validator.sanitizes && validator.sanitizes.length > 0) {
      // Check if sanitization covers common attack patterns for this CVE
      const attackPatterns = this.getAttackPatterns(finding);
      const covered = attackPatterns.some((pattern) => validator.sanitizes?.includes(pattern));

      if (covered) {
        return {
          reason: `Input validation sanitizes attack vector: ${validator.sanitizes.join(', ')}`,
          severity: 'high',
          evidence: `Validator: ${validator.validates || 'strict'}`,
        };
      }
    }

    if (validator.schema) {
      return {
        reason: `Strict input validation enforced: ${validator.schema}`,
        severity: 'medium',
        evidence: `Schema validation active`,
      };
    }

    return null;
  }

  /**
   * Extract common attack patterns for a given CVE
   * (in real impl, would match against CVE database)
   */
  private getAttackPatterns(finding: VulnerabilityFinding): string[] {
    const cveId = finding.vulnerability.cve_id;

    // Example mappings for common prototype pollution / injection patterns
    const patterns: Record<string, string[]> = {
      'CVE-2023-54321': ['__proto__', 'constructor', 'prototype'],
      'CVE-2023-12345': ['body-parser', 'express-router'],
    };

    return patterns[cveId] || [];
  }

  /**
   * Simple wildcard endpoint matching
   * e.g., "/api/*" matches "/api/users", "/api/data", etc.
   */
  private matchesEndpoint(actual: string, pattern: string): boolean {
    if (pattern === '*') return true;
    if (pattern === actual) return true;

    // Wildcard matching: "/api/*" matches "/api/..."
    if (pattern.endsWith('/*')) {
      const prefix = pattern.slice(0, -2);
      return actual.startsWith(prefix);
    }

    return false;
  }
}

/**
 * Factory function to create processor from YAML/JSON context
 */
export function createContextProcessor(context: HawkeyeContext): ContextProcessor {
  return new ContextProcessor(context);
}
