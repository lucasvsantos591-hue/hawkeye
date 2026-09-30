import * as fs from 'fs';
import * as path from 'path';

export interface TerraformSecurityGroup {
  name: string;
  ingress: Array<{
    from_port: number;
    to_port: number;
    protocol: string;
    cidr_blocks: string[];
  }>;
}

export interface TerraformWAF {
  name: string;
  enabled: boolean;
}

export interface TerraformContext {
  securityGroups: TerraformSecurityGroup[];
  wafRules: TerraformWAF[];
  loadBalancers: Array<{ name: string; type: string }>;
  publiclyAccessible: boolean;
  exposureLevel: 'internet-facing' | 'internal-only';
}

/**
 * Parses Terraform files for security context
 */
export class TerraformParser {
  /**
   * Extract context from terraform files
   */
  static extractContext(projectPath: string): TerraformContext | null {
    const tfDir = path.join(projectPath, 'terraform');
    const infraDir = path.join(projectPath, 'infrastructure');

    let contextDir: string | null = null;
    if (fs.existsSync(tfDir)) {
      contextDir = tfDir;
    } else if (fs.existsSync(infraDir)) {
      contextDir = infraDir;
    }

    if (!contextDir) {
      return null;
    }

    return this.parseTerraformDirectory(contextDir);
  }

  /**
   * Parse terraform directory
   */
  private static parseTerraformDirectory(dirPath: string): TerraformContext {
    const securityGroups: TerraformSecurityGroup[] = [];
    const wafRules: TerraformWAF[] = [];
    const loadBalancers: Array<{ name: string; type: string }> = [];
    let publiclyAccessible = false;

    try {
      const files = fs.readdirSync(dirPath);

      for (const file of files) {
        if (!file.endsWith('.tf')) {
          continue;
        }

        const filePath = path.join(dirPath, file);
        const content = fs.readFileSync(filePath, 'utf-8');

        // Parse security groups
        const sgMatches = content.match(
          /resource\s+"aws_security_group"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g,
        );
        if (sgMatches) {
          for (const match of sgMatches) {
            const sg = this.parseSecurityGroup(match);
            if (sg) {
              securityGroups.push(sg);
              // Check for public access
              if (sg.ingress.some(r => r.cidr_blocks.includes('0.0.0.0/0'))) {
                publiclyAccessible = true;
              }
            }
          }
        }

        // Parse WAF rules
        const wafMatches = content.match(
          /resource\s+"aws_wafv2_web_acl"\s+"([^"]+)"\s*\{/g,
        );
        if (wafMatches) {
          for (const match of wafMatches) {
            const name = match.match(/"([^"]+)"/)?.[1] || 'unknown';
            wafRules.push({ name, enabled: true });
            publiclyAccessible = true; // WAF usually means internet-facing
          }
        }

        // Parse load balancers
        const albMatches = content.match(/resource\s+"aws_lb"\s+"([^"]+)"/g);
        if (albMatches) {
          for (const match of albMatches) {
            const name = match.match(/"([^"]+)"/)?.[1] || 'unknown';
            loadBalancers.push({ name, type: 'alb' });
            publiclyAccessible = true;
          }
        }

        const nlbMatches = content.match(
          /resource\s+"aws_network_load_balancer"\s+"([^"]+)"/g,
        );
        if (nlbMatches) {
          for (const match of nlbMatches) {
            const name = match.match(/"([^"]+)"/)?.[1] || 'unknown';
            loadBalancers.push({ name, type: 'nlb' });
          }
        }
      }
    } catch (error) {
      console.warn(`Failed to parse terraform directory:`, error);
    }

    return {
      securityGroups,
      wafRules,
      loadBalancers,
      publiclyAccessible,
      exposureLevel: publiclyAccessible ? 'internet-facing' : 'internal-only',
    };
  }

  /**
   * Parse a security group resource
   */
  private static parseSecurityGroup(text: string): TerraformSecurityGroup | null {
    const nameMatch = text.match(/"([^"]+)"/);
    if (!nameMatch) {
      return null;
    }

    const name = nameMatch[1];
    const ingress: TerraformSecurityGroup['ingress'] = [];

    // Simple regex to find ingress blocks
    const ingressMatches = text.match(
      /ingress\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g,
    );
    if (ingressMatches) {
      for (const match of ingressMatches) {
        const rule = this.parseIngressRule(match);
        if (rule) {
          ingress.push(rule);
        }
      }
    }

    return { name, ingress };
  }

  /**
   * Parse an ingress rule
   */
  private static parseIngressRule(text: string): TerraformSecurityGroup['ingress'][0] | null {
    const fromPort = this.extractNumber(text, /from_port\s*=\s*(\d+)/);
    const toPort = this.extractNumber(text, /to_port\s*=\s*(\d+)/);
    const protocol = this.extractString(text, /protocol\s*=\s*"([^"]+)"/);
    const cidrBlocks = this.extractArray(text, /cidr_blocks\s*=\s*\[(.*?)\]/);

    return {
      from_port: fromPort || 0,
      to_port: toPort || 65535,
      protocol: protocol || 'tcp',
      cidr_blocks: cidrBlocks,
    };
  }

  private static extractNumber(text: string, regex: RegExp): number | null {
    const match = text.match(regex);
    return match ? parseInt(match[1], 10) : null;
  }

  private static extractString(text: string, regex: RegExp): string | null {
    const match = text.match(regex);
    return match ? match[1] : null;
  }

  private static extractArray(text: string, regex: RegExp): string[] {
    const match = text.match(regex);
    if (!match) {
      return [];
    }

    const arrayContent = match[1];
    return arrayContent
      .split(',')
      .map(s => s.trim().replace(/^"/, '').replace(/"$/, ''))
      .filter(s => s.length > 0);
  }
}
