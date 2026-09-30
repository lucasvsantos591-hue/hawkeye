import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export type NetworkExposure = 'internet-facing' | 'internal-only' | 'isolated' | 'unknown';

export interface HawkeyeContextConfig {
  application_name?: string;
  environment?: 'development' | 'staging' | 'production';
  exposure?: NetworkExposure;
  network_location?: {
    // AWS
    aws_region?: string;
    aws_security_groups?: string[];
    // Azure
    azure_region?: string;
    azure_network_security_groups?: string[];
    // Network
    public_ips?: string[];
    private_ips?: string[];
  };
  compliance?: {
    pci_dss?: boolean;
    hipaa?: boolean;
    gdpr?: boolean;
    soc2?: boolean;
    iso27001?: boolean;
  };
  custom_tags?: Record<string, string>;
}

export interface HawkeyeContext {
  config: HawkeyeContextConfig;
  sourceFile: string;
  sourceFormat: 'json' | 'yaml';
}

export class ContextLoader {
  /**
   * Load context from file (.hawkeye.json or .hawkeye.yaml)
   */
  static loadContext(projectPath: string): HawkeyeContext | null {
    const candidates = [
      path.join(projectPath, '.hawkeye.json'),
      path.join(projectPath, '.hawkeye.yaml'),
      path.join(projectPath, '.hawkeye.yml'),
      path.join(projectPath, 'hawkeye.json'),
      path.join(projectPath, 'hawkeye.yaml'),
      path.join(projectPath, 'hawkeye.yml'),
    ];

    for (const filePath of candidates) {
      if (fs.existsSync(filePath)) {
        return this.loadContextFromFile(filePath);
      }
    }

    return null;
  }

  /**
   * Load context from specific file
   */
  static loadContextFromFile(filePath: string): HawkeyeContext | null {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const ext = path.extname(filePath).toLowerCase();

      let config: HawkeyeContextConfig;
      let sourceFormat: 'json' | 'yaml';

      if (ext === '.json') {
        config = JSON.parse(content);
        sourceFormat = 'json';
      } else if (ext === '.yaml' || ext === '.yml') {
        config = yaml.load(content) as HawkeyeContextConfig;
        sourceFormat = 'yaml';
      } else {
        // Try to detect format
        try {
          config = JSON.parse(content);
          sourceFormat = 'json';
        } catch {
          config = yaml.load(content) as HawkeyeContextConfig;
          sourceFormat = 'yaml';
        }
      }

      return {
        config,
        sourceFile: filePath,
        sourceFormat,
      };
    } catch (error) {
      console.error(`Failed to load context from ${filePath}:`, error);
      return null;
    }
  }

  /**
   * Validate context configuration
   */
  static validateContext(context: HawkeyeContext): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!context.config) {
      errors.push('Missing config object');
    }

    if (context.config.exposure && !this.isValidExposure(context.config.exposure)) {
      errors.push(`Invalid exposure value: ${context.config.exposure}`);
    }

    if (context.config.environment && !this.isValidEnvironment(context.config.environment)) {
      errors.push(`Invalid environment value: ${context.config.environment}`);
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Get exposure level from context
   */
  static getExposure(context: HawkeyeContext | null): NetworkExposure {
    if (!context) {
      return 'unknown';
    }

    return context.config.exposure || 'unknown';
  }

  /**
   * Check if application is internet-facing
   */
  static isInternetFacing(context: HawkeyeContext | null): boolean {
    const exposure = this.getExposure(context);
    return exposure === 'internet-facing';
  }

  /**
   * Check if application is isolated
   */
  static isIsolated(context: HawkeyeContext | null): boolean {
    const exposure = this.getExposure(context);
    return exposure === 'isolated';
  }

  /**
   * Create default context
   */
  static createDefaultContext(): HawkeyeContext {
    return {
      config: {
        exposure: 'unknown',
      },
      sourceFile: 'default',
      sourceFormat: 'json',
    };
  }

  /**
   * Export context to JSON
   */
  static toJSON(context: HawkeyeContext): string {
    return JSON.stringify(
      {
        config: context.config,
        sourceFile: context.sourceFile,
        sourceFormat: context.sourceFormat,
      },
      null,
      2,
    );
  }

  /**
   * Export context to YAML
   */
  static toYAML(context: HawkeyeContext): string {
    return yaml.dump(
      {
        config: context.config,
        sourceFile: context.sourceFile,
        sourceFormat: context.sourceFormat,
      },
      { indent: 2 },
    );
  }

  // Private helpers
  private static isValidExposure(exposure: string): boolean {
    return ['internet-facing', 'internal-only', 'isolated', 'unknown'].includes(exposure);
  }

  private static isValidEnvironment(environment: string): boolean {
    return ['development', 'staging', 'production'].includes(environment);
  }
}

/**
 * Example context file (.hawkeye.yaml):
 *
 * application_name: my-app
 * environment: production
 * exposure: internet-facing
 *
 * network_location:
 *   aws_region: us-east-1
 *   aws_security_groups:
 *     - sg-12345
 *   public_ips:
 *     - 203.0.113.0
 *
 * compliance:
 *   pci_dss: true
 *   gdpr: true
 *
 * custom_tags:
 *   team: security
 *   owner: john@example.com
 */
