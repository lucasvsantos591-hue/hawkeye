import * as fs from 'fs';
import type { HawkeyeContext } from '../../types/context.js';

/**
 * Load Hawkeye context from JSON file
 *
 * Supports:
 * - hawkeye-context.json (recommended for v1)
 * - Custom path via CLI flag --context
 *
 * YAML support will be added in v2.x with optional 'js-yaml' dependency
 */
export function loadContext(filePath: string): HawkeyeContext {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Context file not found: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, 'utf-8');

  // Only JSON support for now
  if (!filePath.endsWith('.json')) {
    console.warn(
      `⚠️ YAML files require 'js-yaml' package (v2.2+). Using JSON format recommended for now.`,
    );
  }

  try {
    const parsed = JSON.parse(content);
    validateContext(parsed);
    return parsed;
  } catch (error) {
    throw new Error(`Invalid JSON in ${filePath}: ${(error as Error).message}`);
  }
}

/**
 * Validate context structure
 */
function validateContext(context: HawkeyeContext): void {
  // Basic validation — extend as needed
  if (context.application?.internet_facing !== undefined && typeof context.application.internet_facing !== 'boolean') {
    throw new Error('application.internet_facing must be boolean');
  }

  if (context.authentication?.gates) {
    if (!Array.isArray(context.authentication.gates)) {
      throw new Error('authentication.gates must be array');
    }

    for (const gate of context.authentication.gates) {
      if (typeof gate.endpoint !== 'string' || typeof gate.gate !== 'string') {
        throw new Error('Each gate must have endpoint and gate (strings)');
      }
    }
  }

  if (context.network?.firewall_rules) {
    if (!Array.isArray(context.network.firewall_rules)) {
      throw new Error('network.firewall_rules must be array');
    }
  }

  if (context.validation?.validators) {
    if (!Array.isArray(context.validation.validators)) {
      throw new Error('validation.validators must be array');
    }
  }
}
