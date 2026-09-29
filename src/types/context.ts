/**
 * Hawkeye Context Schema
 *
 * Allows security teams to provide infrastructure, network, and authentication
 * context that can reduce reachability scoring in the report.
 *
 * Example: A CVE marked as Level 3 (taint-reachable) in code analysis
 * might be Level 1 in reality if the vulnerable endpoint is behind auth,
 * blocked by WAF, or isolated by network segmentation.
 */

export interface ApplicationContext {
  name: string;
  description?: string;
  internet_facing?: boolean;
  environment?: 'production' | 'staging' | 'development';
}

export interface FirewallRule {
  endpoint: string;
  blocked?: boolean;
  reason?: string;
  waf?: string;
  rate_limit?: string;
}

export interface NetworkContext {
  firewall_rules?: FirewallRule[];
  segmentation?: Record<string, string>;
  allowed_ips?: string[];
  vpc_internal?: boolean;
}

export interface AuthGate {
  endpoint: string;
  gate: string;
  bypass?: boolean;
  description?: string;
}

export interface AuthenticationContext {
  gates?: AuthGate[];
  default_requires_auth?: boolean;
}

export interface InputValidator {
  endpoint: string;
  validates?: string;
  sanitizes?: string[];
  schema?: string;
}

export interface ValidationContext {
  validators?: InputValidator[];
}

export interface HawkeyeContext {
  application?: ApplicationContext;
  network?: NetworkContext;
  authentication?: AuthenticationContext;
  validation?: ValidationContext;
  custom?: Record<string, unknown>;
}

/**
 * Mitigation reason for reachability adjustment
 */
export interface ContextMitigation {
  reason: string;
  severity?: 'high' | 'medium' | 'low';
  evidence?: string;
}

/**
 * Extended finding with context applied
 */
export interface ContextualizedFinding {
  cve_id: string;
  original_reachability_level: 1 | 2 | 3;
  adjusted_reachability_level: 1 | 2 | 3;
  mitigations: ContextMitigation[];
  context_applied: boolean;
}
