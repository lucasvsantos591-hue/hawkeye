/**
 * Detects network exposure of an application based on:
 * - Infrastructure configuration (AWS, Azure, K8s)
 * - Network policies
 * - WAF rules
 * - Security groups
 */

export interface ExposureDetectionResult {
  exposure: 'internet-facing' | 'internal-only' | 'isolated';
  confidence: number; // 0-100
  reasons: string[];
  publicIPs?: string[];
  publicPorts?: number[];
  publicDomains?: string[];
  hasLoadBalancer?: boolean;
  hasCloudFlare?: boolean;
  hasCDN?: boolean;
  securityScore?: number; // 0-100 (higher = more secure)
}

export class ExposureDetector {
  /**
   * Detect exposure from Kubernetes NetworkPolicy
   */
  static detectFromK8sNetworkPolicy(policyYaml: string): ExposureDetectionResult {
    const isIsolated = this.isK8sIsolated(policyYaml);

    return {
      exposure: isIsolated ? 'isolated' : 'internal-only',
      confidence: isIsolated ? 95 : 30,
      reasons: isIsolated
        ? [
            'NetworkPolicy restricts ingress traffic',
            'Pod-to-pod communication restricted by namespace',
          ]
        : ['No explicit NetworkPolicy isolation detected'],
    };
  }

  /**
   * Detect exposure from AWS Security Group
   */
  static detectFromAWSSecurityGroup(sgJson: any): ExposureDetectionResult {
    const publicPorts: number[] = [];
    const reasons: string[] = [];

    if (!sgJson.IpPermissions) {
      return {
        exposure: 'internal-only',
        confidence: 30,
        reasons: ['No security group ingress rules found'],
      };
    }

    let isInternetFacing = false;

    for (const rule of sgJson.IpPermissions) {
      // Check if rule allows traffic from 0.0.0.0/0 (internet)
      for (const ipRange of rule.IpRanges || []) {
        if (ipRange.CidrIp === '0.0.0.0/0') {
          isInternetFacing = true;
          const ports = this.getPorts(rule);
          publicPorts.push(...ports);
          reasons.push(`Port ${ports.join(', ')} open to internet (0.0.0.0/0)`);
        }
      }

      for (const ipv6Range of rule.Ipv6Ranges || []) {
        if (ipv6Range.CidrIpv6 === '::/0') {
          isInternetFacing = true;
          const ports = this.getPorts(rule);
          publicPorts.push(...ports);
          reasons.push(`Port ${ports.join(', ')} open to internet (::/0)`);
        }
      }
    }

    return {
      exposure: isInternetFacing ? 'internet-facing' : 'internal-only',
      confidence: isInternetFacing ? 90 : 85,
      publicPorts: [...new Set(publicPorts)],
      reasons,
    };
  }

  /**
   * Detect exposure from Terraform configuration
   */
  static detectFromTerraformWAF(tfJson: any): ExposureDetectionResult {
    const reasons: string[] = [];
    let hasWAF = false;

    if (tfJson.resources) {
      for (const resource of tfJson.resources) {
        if (resource.type === 'aws_wafv2_web_acl' || resource.type === 'aws_waf_web_acl') {
          hasWAF = true;
          reasons.push('WAF (Web Application Firewall) configured');
        }

        if (resource.type === 'aws_alb' || resource.type === 'aws_lb') {
          reasons.push('Application Load Balancer (ALB) configured');
        }

        if (resource.type === 'aws_cloudfront_distribution') {
          reasons.push('CloudFront CDN configured');
        }
      }
    }

    return {
      exposure: hasWAF ? 'internet-facing' : 'internal-only',
      confidence: hasWAF ? 70 : 20,
      hasCDN: tfJson.resources?.some((r: any) => r.type === 'aws_cloudfront_distribution'),
      reasons: hasWAF ? reasons : ['No WAF configuration found'],
    };
  }

  /**
   * Detect exposure from environment variables
   */
  static detectFromEnvironment(env: Record<string, string | undefined>): ExposureDetectionResult {
    const reasons: string[] = [];
    const publicDomains: string[] = [];

    // Check for public domain indicators
    if (env.PUBLIC_URL) {
      publicDomains.push(env.PUBLIC_URL);
      reasons.push(`Public URL configured: ${env.PUBLIC_URL}`);
    }

    if (env.DOMAIN || env.HOSTNAME) {
      const domain = env.DOMAIN || env.HOSTNAME;
      if (!domain?.includes('localhost') && !domain?.includes('127.0.0.1')) {
        publicDomains.push(domain!);
        reasons.push(`Public domain configured: ${domain}`);
      }
    }

    // Check for environment type
    if (env.NODE_ENV === 'production' || env.ENV === 'production') {
      reasons.push('Production environment detected');
    }

    return {
      exposure: publicDomains.length > 0 ? 'internet-facing' : 'internal-only',
      confidence: publicDomains.length > 0 ? 60 : 20,
      publicDomains,
      reasons: reasons.length > 0 ? reasons : ['No public domain detected'],
    };
  }

  /**
   * Combine multiple exposure detection results
   */
  static combine(...results: ExposureDetectionResult[]): ExposureDetectionResult {
    const allReasons = results.flatMap(r => r.reasons);
    const allPublicPorts = results.flatMap(r => r.publicPorts || []);
    const allPublicDomains = results.flatMap(r => r.publicDomains || []);

    // Determine exposure based on individual results
    const internetFacing = results.some(r => r.exposure === 'internet-facing');
    const isolated = results.some(r => r.exposure === 'isolated');

    let exposure: 'internet-facing' | 'internal-only' | 'isolated';
    if (internetFacing) {
      exposure = 'internet-facing';
    } else if (isolated) {
      exposure = 'isolated';
    } else {
      exposure = 'internal-only';
    }

    // Average confidence
    const avgConfidence =
      results.filter(r => r.confidence > 0).length > 0
        ? Math.round(
            results.filter(r => r.confidence > 0).reduce((sum, r) => sum + r.confidence, 0) /
              results.filter(r => r.confidence > 0).length,
          )
        : 0;

    return {
      exposure,
      confidence: Math.min(100, avgConfidence),
      reasons: [...new Set(allReasons)],
      publicPorts: [...new Set(allPublicPorts)],
      publicDomains: [...new Set(allPublicDomains)],
    };
  }

  // Private helpers
  private static isK8sIsolated(policyYaml: string): boolean {
    // Check if NetworkPolicy has deny-all ingress rules
    return (
      policyYaml.includes('policyTypes:') &&
      policyYaml.includes('Ingress') &&
      !policyYaml.includes('ingress:') &&
      policyYaml.includes('- {}')
    );
  }

  private static getPorts(rule: any): number[] {
    const ports: number[] = [];

    if (rule.FromPort && rule.ToPort) {
      for (let p = rule.FromPort; p <= rule.ToPort; p++) {
        ports.push(p);
      }
    }

    return ports;
  }
}
