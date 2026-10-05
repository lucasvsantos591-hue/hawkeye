import { AnalysisResult, VulnerabilityFinding } from '../../types/analysis-result.js';
import type { HawkeyeContext } from '../context/context_loader.js';
import { RiskRescorer, RescoreResult, findingKey } from '../../core/risk_rescorer.js';
import { escapeHtml as e, safeUrl, shownPath } from './escape.js';
import { epssLabel, epssSummaryLine, kevCatalogLine, kevLabel } from './threat_labels.js';

/**
 * Renders analysis results as HTML report with exposure context
 */
export class HTMLReportRenderer {
  private result: AnalysisResult;
  private rescorer: RiskRescorer;
  private rescores: Map<string, RescoreResult>;
  private aiProvider?: string;

  constructor(result: AnalysisResult, context?: HawkeyeContext | null, aiProvider?: string) {
    this.result = result;
    this.rescorer = new RiskRescorer(context);
    this.rescores = this.rescorer.rescoreFindings(result.results);
    this.aiProvider = aiProvider;
  }

  /**
   * Render complete HTML report
   */
  render(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
  <title>Hawkeye Vulnerability Report - ${e(this.result.project_name)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
      background: #f5f5f5;
      padding: 20px;
    }
    .container { max-width: 1200px; margin: 0 auto; }

    header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 30px;
      border-radius: 8px;
      margin-bottom: 30px;
    }

    h1 { font-size: 2em; margin-bottom: 10px; }
    .metadata { display: flex; gap: 30px; flex-wrap: wrap; margin-top: 20px; }
    .metadata-item { flex: 1; min-width: 150px; }
    .metadata-label { font-size: 0.9em; opacity: 0.9; }
    .metadata-value { font-size: 1.1em; font-weight: 600; }

    .exposure-badge {
      display: inline-block;
      padding: 8px 16px;
      border-radius: 4px;
      font-weight: 600;
      font-size: 0.9em;
      margin-top: 10px;
    }

    .exposure-internet { background: #ff6b6b; color: white; }
    .exposure-internal { background: #ffa94d; color: white; }
    .exposure-isolated { background: #51cf66; color: white; }
    .exposure-unknown { background: #adb5bd; color: white; }

    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }

    .summary-card {
      background: white;
      padding: 20px;
      border-radius: 8px;
      border-left: 4px solid #667eea;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .summary-card.critical { border-left-color: #ff6b6b; }
    .summary-card.high { border-left-color: #ffa94d; }
    .summary-card.medium { border-left-color: #4ecdc4; }
    .summary-card.low { border-left-color: #adb5bd; }

    .summary-label { color: #666; font-size: 0.9em; }
    .summary-value { font-size: 2em; font-weight: 700; color: #333; margin-top: 10px; }

    .rescoring-notice {
      background: #e7f5ff;
      border: 1px solid #a5d8ff;
      border-radius: 4px;
      padding: 15px;
      margin-bottom: 20px;
    }

    .rescoring-notice strong { color: #1971c2; }

    .vulnerabilities {
      display: flex;
      flex-direction: column;
      gap: 15px;
    }

    .vuln-card {
      background: white;
      border-radius: 8px;
      padding: 20px;
      border-left: 4px solid #ddd;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .vuln-card.critical { border-left-color: #ff6b6b; }
    .vuln-card.high { border-left-color: #ffa94d; }
    .vuln-card.medium { border-left-color: #4ecdc4; }
    .vuln-card.low { border-left-color: #95a5a6; }

    .vuln-header {
      display: flex;
      justify-content: space-between;
      align-items: start;
      gap: 20px;
      margin-bottom: 15px;
    }

    .vuln-title {
      flex: 1;
    }

    .vuln-cve {
      font-size: 0.9em;
      color: #666;
      margin-bottom: 5px;
    }

    .vuln-package {
      font-weight: 600;
      color: #333;
      margin-bottom: 5px;
    }

    .score-badge {
      background: #f0f0f0;
      padding: 8px 12px;
      border-radius: 4px;
      font-weight: 600;
      font-size: 0.85em;
      white-space: nowrap;
    }

    .score-badge.original { color: #666; }
    .score-badge.adjusted { background: #e7f5ff; color: #1971c2; }

    .multiplier-badge {
      background: #fff3cd;
      color: #856404;
      padding: 4px 8px;
      border-radius: 3px;
      font-size: 0.85em;
      font-weight: 600;
    }

    .vuln-details {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 15px;
      margin-top: 15px;
      font-size: 0.9em;
    }

    .detail-item { }
    .detail-label { color: #999; font-size: 0.85em; }
    .detail-value { color: #333; font-weight: 500; }

    .tags {
      display: flex;
      gap: 8px;
      margin-top: 10px;
      flex-wrap: wrap;
    }

    .tag {
      background: #f0f0f0;
      padding: 4px 8px;
      border-radius: 3px;
      font-size: 0.8em;
      color: #666;
    }

    .tag.reachable { background: #ffe7e7; color: #c92a2a; }
    .tag.exploited { background: #ffe7e7; color: #c92a2a; }

    footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #ddd;
      color: #666;
      font-size: 0.9em;
    }
  </style>
</head>
<body>
  <div class="container">
    ${this.renderHeader()}
    ${this.renderSummary()}
    ${this.renderScanInfo()}
    ${this.renderRescoringSummary()}
    ${this.renderVulnerabilities()}
    ${this.renderFooter()}
  </div>
</body>
</html>`;
  }

  private renderHeader(): string {
    const exposure = this.rescorer.getExposure();
    const exposureClass = `exposure-${exposure || 'unknown'}`;

    return `<header>
      <h1>🎯 Hawkeye Vulnerability Report</h1>
      <p>${e(this.result.project_name)}</p>
      <div class="metadata">
        ${shownPath(this.result.project_path) ? `<div class="metadata-item">
          <div class="metadata-label">Project Path</div>
          <div class="metadata-value">${e(shownPath(this.result.project_path))}</div>
        </div>` : ''}
        <div class="metadata-item">
          <div class="metadata-label">Generated</div>
          <div class="metadata-value">${e(new Date(this.result.generated_at).toLocaleString())}</div>
        </div>
        <div class="metadata-item">
          <div class="metadata-label">Network Exposure</div>
          <div class="exposure-badge ${e(exposureClass)}">${e(exposure || 'Unknown')}</div>
        </div>
      </div>
    </header>`;
  }

  private renderSummary(): string {
    // Counted from the findings, so results written before low_reachable existed still add up.
    const count = (severity: string) =>
      this.result.results.filter(f => f.is_reachable && f.vulnerability.severity === severity).length;

    return `<div class="summary">
      <div class="summary-card critical">
        <div class="summary-label">Critical Vulnerabilities</div>
        <div class="summary-value">${e(count('CRITICAL'))}</div>
      </div>
      <div class="summary-card high">
        <div class="summary-label">High Severity</div>
        <div class="summary-value">${e(count('HIGH'))}</div>
      </div>
      <div class="summary-card medium">
        <div class="summary-label">Medium Severity</div>
        <div class="summary-value">${e(count('MEDIUM'))}</div>
      </div>
      <div class="summary-card low">
        <div class="summary-label">Low Severity</div>
        <div class="summary-value">${e(count('LOW'))}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Risk Score</div>
        <div class="summary-value">${e(this.result.overall_risk_score)}</div>
      </div>
    </div>`;
  }

  private renderRescoringSummary(): string {
    const summary = this.rescorer.getSummary(this.result.results);

    if (summary.averageMultiplier === 1.0) {
      return '';
    }

    const direction = summary.averageMultiplier > 1.0 ? '↑ Increased' : '↓ Decreased';
    const percentChange = Math.abs(
      Math.round((summary.averageMultiplier - 1.0) * 100)
    );

    return `<div class="rescoring-notice">
      <strong>⚠️ Risk Rescoring Applied:</strong><br>
      Application exposure: <strong>${e(summary.exposure)}</strong><br>
      Risk scores adjusted by <strong>${direction} ${percentChange}%</strong> based on network exposure.
      <br>Critical findings: ${e(summary.originalCritical)} → ${e(summary.adjustedCritical)}
    </div>`;
  }

  private renderVulnerabilities(): string {
    if (this.result.results.length === 0) {
      return '<p style="text-align: center; padding: 40px; color: #666;">No vulnerabilities found! ✅</p>';
    }

    const vulns = this.result.results.map(finding => this.renderVulnerability(finding)).join('');

    return `<div class="vulnerabilities">${vulns}</div>`;
  }

  private renderScanInfo(): string {
    const scan = this.result.scan;
    if (!scan) return '';
    const warnings = scan.warnings.map(w => `<li>${e(w)}</li>`).join('');
    const kev = kevCatalogLine(this.result);
    const epss = epssSummaryLine(this.result);
    return `<div class="rescoring-notice">
      <strong>Scan:</strong> ${e(scan.packages_scanned)} packages (${e(scan.dependency_source)}),
      ${e(scan.files_scanned)} source files, advisories from ${e(scan.vulnerability_source)}.
      ${scan.include_dev ? '' : 'Dev-only dependencies excluded.'}
      ${kev ? `<br>${e(kev)}` : ''}
      ${epss ? `<br>${e(epss)}` : ''}
      ${warnings ? `<ul style="margin: 8px 0 0 20px;">${warnings}</ul>` : ''}
    </div>`;
  }

  private renderVulnerability(finding: VulnerabilityFinding): string {
    const v = finding.vulnerability;
    const rescore = this.rescores.get(findingKey(finding));
    const riskLevel = finding.is_reachable ? rescore?.riskLevel.toLowerCase() || 'medium' : 'low';

    const tags: string[] = [];
    tags.push(
      finding.is_reachable
        ? '<span class="tag reachable">Reachable</span>'
        : '<span class="tag">Not reachable</span>',
    );
    if (v.is_exploited_in_wild) tags.push('<span class="tag exploited">CISA KEV: exploited in the wild</span>');
    if (v.ecosystem) tags.push(`<span class="tag">${e(v.ecosystem)}</span>`);
    if (v.project && v.project !== '.') tags.push(`<span class="tag">${e(v.project)}</span>`);
    if (v.dependency_type) tags.push(`<span class="tag">${e(v.dependency_type)}</span>`);
    if (v.is_dev) tags.push('<span class="tag">dev</span>');

    const link = safeUrl(v.advisory_url);
    const title = v.advisory_id && v.advisory_id !== v.cve_id ? `${v.cve_id} · ${v.advisory_id}` : v.cve_id;
    const via = v.introduced_via?.length ? `<div class="detail-item"><div class="detail-label">Introduced via</div><div class="detail-value">${e(v.introduced_via.join(', '))}</div></div>` : '';
    const sites = finding.evidence?.sites.length
      ? `<div style="margin-top: 8px; font-size: 0.85em;"><strong>Used at:</strong> ${finding.evidence.sites.map(x => `<code>${e(x)}</code>`).join(' ')}</div>`
      : '';

    return `<div class="vuln-card ${e(riskLevel)}">
      <div class="vuln-header">
        <div class="vuln-title">
          <div class="vuln-cve">${link ? `<a href="${link}" rel="noopener noreferrer">${e(title)}</a>` : e(title)}</div>
          <div class="vuln-package">${e(v.package)}@${e(v.current_version)}</div>
          ${v.summary ? `<div style="color: #444; margin-top: 4px;">${e(v.summary)}</div>` : ''}
        </div>
        <div>
          <div class="score-badge original">Score: ${e(rescore?.originalScore ?? 0)}</div>
          ${rescore && rescore.multiplier !== 1.0 ? `<div class="score-badge adjusted">Adjusted: ${e(rescore.adjustedScore)}</div><div class="multiplier-badge">×${e(rescore.multiplier.toFixed(1))}</div>` : ''}
        </div>
      </div>

      <div class="vuln-details">
        <div class="detail-item"><div class="detail-label">Severity</div><div class="detail-value">${e(v.severity)}</div></div>
        <div class="detail-item"><div class="detail-label">Fixed in</div><div class="detail-value">${e(v.fixed_version ?? 'no fix published')}</div></div>
        <div class="detail-item"><div class="detail-label">Reachability</div><div class="detail-value">Level ${e(finding.reachability_level)} · ${e(finding.confidence)}% confidence</div></div>
        <div class="detail-item"><div class="detail-label">EPSS (30-day exploit probability)</div><div class="detail-value">${e(epssLabel(v, this.result))}</div></div>
        <div class="detail-item"><div class="detail-label">CISA KEV</div><div class="detail-value">${e(kevLabel(v, this.result))}</div></div>
        ${via}
      </div>

      ${finding.reason ? `<div style="margin-top: 10px; font-size: 0.9em; color: #444;">${e(finding.reason)}</div>` : ''}
      ${sites}

      ${finding.remediation ? `<div style="margin-top: 15px; padding: 10px; background: #f0f9ff; border-left: 3px solid #0066cc; border-radius: 3px;">
        <strong>Remediation${this.aiProvider ? ' (AI-generated, verify before running)' : ''}:</strong> ${e(finding.remediation.description)}
        ${finding.remediation.action ? `<br/><code>${e(finding.remediation.action)}</code>` : ''}
      </div>` : ''}

      <div class="tags">
        ${tags.join('')}
      </div>
    </div>`;
  }

  private renderFooter(): string {
    const ai = this.aiProvider ? `<p>Powered by ${e(this.aiProvider)} for AI-assisted remediations</p>` : '';
    return `<footer>
      <p>Generated by Hawkeye${this.result.scan ? ` v${e(this.result.scan.tool_version)}` : ''} · schema ${e(this.result.schema_version)}</p>
      ${ai}
    </footer>`;
  }
}
