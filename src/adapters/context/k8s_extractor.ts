import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export interface K8sNetworkPolicy {
  name: string;
  namespace: string;
  policyTypes: string[];
  ingressRules: any[];
  egressRules: any[];
  podSelector: any;
}

export interface K8sContext {
  namespace: string;
  networkPolicies: K8sNetworkPolicy[];
  isIsolated: boolean;
  exposureLevel: 'isolated' | 'internal-only' | 'internet-facing';
}

/**
 * Extracts Kubernetes context from NetworkPolicy files
 */
export class K8sExtractor {
  /**
   * Extract context from k8s files
   */
  static extractContext(projectPath: string): K8sContext | null {
    const k8sDir = path.join(projectPath, 'k8s');
    const kubernetesDir = path.join(projectPath, 'kubernetes');

    let contextDir: string | null = null;
    if (fs.existsSync(k8sDir)) {
      contextDir = k8sDir;
    } else if (fs.existsSync(kubernetesDir)) {
      contextDir = kubernetesDir;
    }

    if (!contextDir) {
      return null;
    }

    return this.parseK8sDirectory(contextDir);
  }

  /**
   * Parse k8s directory for network policies
   */
  private static parseK8sDirectory(dirPath: string): K8sContext {
    const networkPolicies: K8sNetworkPolicy[] = [];
    let namespace = 'default';
    let isIsolated = false;

    try {
      const files = fs.readdirSync(dirPath);

      for (const file of files) {
        if (!file.endsWith('.yaml') && !file.endsWith('.yml')) {
          continue;
        }

        const filePath = path.join(dirPath, file);
        const content = fs.readFileSync(filePath, 'utf-8');

        try {
          const docs = yaml.loadAll(content);

          for (const doc of docs) {
            if (!doc) continue;

            const k8sObj = doc as any;

            // Extract namespace
            if (k8sObj.metadata?.namespace) {
              namespace = k8sObj.metadata.namespace;
            }

            // Extract NetworkPolicy
            if (k8sObj.kind === 'NetworkPolicy') {
              const policy = this.parseNetworkPolicy(k8sObj);
              networkPolicies.push(policy);

              // Check if there's a deny-all ingress rule
              if (
                k8sObj.spec?.policyTypes?.includes('Ingress') &&
                (!k8sObj.spec?.ingress || k8sObj.spec.ingress.length === 0)
              ) {
                isIsolated = true;
              }
            }
          }
        } catch (error) {
          console.warn(`Failed to parse ${file}:`, error);
        }
      }
    } catch (error) {
      console.error(`Failed to read k8s directory:`, error);
    }

    const exposureLevel = isIsolated ? 'isolated' : 'internal-only';

    return {
      namespace,
      networkPolicies,
      isIsolated,
      exposureLevel,
    };
  }

  /**
   * Parse a single NetworkPolicy resource
   */
  private static parseNetworkPolicy(resource: any): K8sNetworkPolicy {
    const spec = resource.spec || {};

    return {
      name: resource.metadata?.name || 'unknown',
      namespace: resource.metadata?.namespace || 'default',
      policyTypes: spec.policyTypes || [],
      ingressRules: spec.ingress || [],
      egressRules: spec.egress || [],
      podSelector: spec.podSelector || {},
    };
  }

  /**
   * Analyze isolation level
   */
  static analyzeIsolation(context: K8sContext): {
    isolated: boolean;
    allowsInbound: boolean;
    allowsOutbound: boolean;
    reason: string;
  } {
    const hasIngressPolicy =
      context.networkPolicies.some(p => p.policyTypes.includes('Ingress')) &&
      context.networkPolicies.some(p => p.ingressRules.length === 0);

    const hasEgressPolicy =
      context.networkPolicies.some(p => p.policyTypes.includes('Egress')) &&
      context.networkPolicies.some(p => p.egressRules.length === 0);

    return {
      isolated: hasIngressPolicy && hasEgressPolicy,
      allowsInbound: !hasIngressPolicy,
      allowsOutbound: !hasEgressPolicy,
      reason: hasIngressPolicy
        ? 'Ingress traffic restricted by NetworkPolicy'
        : 'No ingress restrictions configured',
    };
  }
}
