import type { VulnerabilityFinding } from '../../types/analysis-result.js';
import type { AIProvider } from './ai_provider.interface.js';
import { AI_BATCH_SIZE, findingForId } from './prompts.js';

export interface EnrichmentSummary {
  /** Findings that received at least one AI field. */
  enriched: number;
  batches: number;
  failedBatches: number;
  warnings: string[];
}

/**
 * Adds AI suggestions (code changes, effort, notes) to the findings' remediations, in batches so one long or
 * failed answer only loses its own batch. Fields that already hold a value are never overwritten, and the
 * engine's description, version, command and type are never touched. Remediations that got AI content are
 * marked with `ai_provider`, so reports can label that content.
 */
export async function enrichRemediations(
  findings: VulnerabilityFinding[],
  provider: AIProvider,
  batchSize = AI_BATCH_SIZE,
): Promise<EnrichmentSummary> {
  const summary: EnrichmentSummary = { enriched: 0, batches: 0, failedBatches: 0, warnings: [] };
  for (let start = 0; start < findings.length; start += batchSize) {
    const batch = findings.slice(start, start + batchSize);
    summary.batches++;
    let suggestions;
    try {
      suggestions = await provider.generateRemediations(batch);
    } catch (error) {
      summary.failedBatches++;
      summary.warnings.push(
        `AI suggestions for findings ${start + 1}-${start + batch.length} failed: ${(error as Error).message}`,
      );
      continue;
    }
    for (const suggestion of suggestions) {
      const finding = findingForId(suggestion.id, batch);
      if (!finding) continue;
      const rem = finding.remediation;
      let added = false;
      if (suggestion.changes_needed?.length && !rem.changes_needed?.length) {
        rem.changes_needed = suggestion.changes_needed;
        added = true;
      }
      if (suggestion.effort_estimate && !rem.effort_estimate) {
        rem.effort_estimate = suggestion.effort_estimate;
        added = true;
      }
      if (suggestion.notes && !rem.notes) {
        rem.notes = suggestion.notes;
        added = true;
      }
      if (added) {
        rem.ai_provider = provider.name;
        summary.enriched++;
      }
    }
  }
  return summary;
}
