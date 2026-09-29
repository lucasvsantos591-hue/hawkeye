import type { AnalysisResult } from '../../types/analysis-result.js';

export interface RenderMeta {
  aiPowered: boolean;
  providerName?: string;
}

export function renderHtmlReport(result: AnalysisResult, meta: RenderMeta): string {
  const reachable = result.results.filter((v) => v.is_reachable);
  const notReachable = result.results.filter((v) => !v.is_reachable);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VRA - Vulnerability Analysis Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: #333;
      padding: 20px;
      min-height: 100vh;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      overflow: hidden;
    }
    header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 40px;
      text-align: center;
    }
    header h1 {
      font-size: 2.5em;
      margin-bottom: 10px;
    }
    header p {
      font-size: 1.1em;
      opacity: 0.9;
    }
    .ai-badge {
      display: inline-block;
      background: rgba(255, 255, 255, 0.2);
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 0.9em;
      margin-left: 10px;
      border: 1px solid rgba(255, 255, 255, 0.4);
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 20px;
      padding: 30px;
      background: #f8f9fa;
      border-bottom: 2px solid #ddd;
    }
    .summary-card {
      text-align: center;
      padding: 20px;
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .summary-card .number {
      font-size: 2.5em;
      font-weight: bold;
      color: #667eea;
      margin-bottom: 10px;
    }
    .summary-card .label {
      font-size: 0.9em;
      color: #666;
      text-transform: uppercase;
    }
    .content {
      padding: 40px;
    }
    .section {
      margin-bottom: 40px;
    }
    .section h2 {
      font-size: 1.8em;
      color: #333;
      margin-bottom: 20px;
      border-bottom: 3px solid #667eea;
      padding-bottom: 10px;
    }
    .vulnerability {
      background: #f8f9fa;
      border-left: 4px solid #667eea;
      padding: 20px;
      margin-bottom: 20px;
      border-radius: 4px;
    }
    .vulnerability.critical {
      border-left-color: #ff4757;
      background: #ffe5e5;
    }
    .vulnerability.high {
      border-left-color: #ff9500;
      background: #fff5e5;
    }
    .vulnerability.medium {
      border-left-color: #ffc107;
      background: #fffde7;
    }
    .vulnerability.low {
      border-left-color: #28a745;
      background: #e8f5e9;
    }
    .vuln-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
      flex-wrap: wrap;
      gap: 10px;
    }
    .vuln-id {
      font-weight: bold;
      font-size: 1.1em;
      color: #333;
    }
    .severity {
      padding: 5px 12px;
      border-radius: 20px;
      font-size: 0.9em;
      font-weight: bold;
      color: white;
    }
    .severity.critical { background: #ff4757; }
    .severity.high { background: #ff9500; }
    .severity.medium { background: #ffc107; color: #333; }
    .severity.low { background: #28a745; }
    .vuln-details {
      font-size: 0.95em;
      line-height: 1.6;
      color: #555;
    }
    .vuln-details p {
      margin-bottom: 10px;
    }
    .remediation-section {
      margin-top: 15px;
      padding-top: 15px;
      border-top: 2px solid #ddd;
      background: #f0f4ff;
      padding: 15px;
      border-radius: 4px;
    }
    .remediation-section h4 {
      color: #667eea;
      margin-bottom: 10px;
    }
    .remediation-type {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.85em;
      font-weight: bold;
      margin-bottom: 10px;
    }
    .remediation-type.major {
      background: #ffcccc;
      color: #cc0000;
    }
    .remediation-type.minor {
      background: #ccffcc;
      color: #009900;
    }
    .remediation-type.optional {
      background: #ccccff;
      color: #0000cc;
    }
    code {
      background: #2d2d2d;
      color: #f8f8f2;
      padding: 15px;
      border-radius: 4px;
      display: block;
      overflow-x: auto;
      font-family: 'Courier New', monospace;
      margin: 10px 0;
      font-size: 0.9em;
      line-height: 1.5;
    }
    .footer {
      background: #f8f9fa;
      padding: 20px;
      text-align: center;
      color: #666;
      border-top: 2px solid #ddd;
      font-size: 0.9em;
    }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      background: #e8e8e8;
      font-size: 0.85em;
      margin-right: 5px;
    }
    ul, ol {
      margin-left: 20px;
      margin-bottom: 10px;
    }
    li {
      margin-bottom: 5px;
    }
    .exposure-section {
      padding: 30px;
      background: #f0f8ff;
      border-left: 5px solid #0066cc;
      margin: 20px 0;
    }
    .exposure-section h3 {
      color: #0066cc;
      margin-bottom: 15px;
      font-size: 1.5em;
    }
    .exposure-status {
      display: flex;
      gap: 20px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .exposure-status-card {
      flex: 1;
      min-width: 200px;
      padding: 15px;
      background: white;
      border-radius: 6px;
      border-left: 4px solid #0066cc;
    }
    .exposure-status-card.internet-facing {
      border-left-color: #ff4757;
    }
    .exposure-status-card.internal-only {
      border-left-color: #28a745;
    }
    .exposure-status-card .status-label {
      font-weight: bold;
      color: #0066cc;
      margin-bottom: 5px;
    }
    .exposure-status-card .status-value {
      font-size: 1.2em;
      color: #333;
    }
    .exposure-details {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-top: 15px;
    }
    .exposure-detail-box {
      padding: 15px;
      background: white;
      border-radius: 6px;
      border: 1px solid #ddd;
    }
    .exposure-detail-box h4 {
      color: #0066cc;
      margin-bottom: 10px;
      font-size: 1.1em;
    }
    .endpoint-item {
      padding: 10px;
      background: #f9f9f9;
      margin-bottom: 8px;
      border-radius: 4px;
      border-left: 3px solid #0066cc;
      font-family: 'Courier New', monospace;
      font-size: 0.95em;
      overflow-x: auto;
    }
    .detection-method {
      display: inline-block;
      background: #e8f4ff;
      color: #0066cc;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.85em;
      margin-right: 5px;
      margin-bottom: 5px;
    }
    .confidence-bar {
      width: 100%;
      height: 24px;
      background: #e0e0e0;
      border-radius: 4px;
      overflow: hidden;
      margin-top: 5px;
    }
    .confidence-fill {
      height: 100%;
      background: linear-gradient(90deg, #28a745, #ffc107);
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-size: 0.85em;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>
        🔍 VRA - Vulnerability Reachability Analysis
        ${meta.aiPowered && meta.providerName ? `<span class="ai-badge">Powered by ${meta.providerName}</span>` : ''}
      </h1>
      <p>Intelligent vulnerability assessment report</p>
    </header>

    <div class="summary">
      <div class="summary-card">
        <div class="number">${result.total_vulnerabilities}</div>
        <div class="label">Total CVEs</div>
      </div>
      <div class="summary-card">
        <div class="number" style="color: #ff4757;">${result.reachable_vulnerabilities}</div>
        <div class="label">Reachable</div>
      </div>
      <div class="summary-card">
        <div class="number" style="color: #28a745;">${result.total_vulnerabilities - result.reachable_vulnerabilities}</div>
        <div class="label">Not Reachable</div>
      </div>
      <div class="summary-card">
        <div class="number">${result.overall_risk_score}</div>
        <div class="label">Risk Score</div>
      </div>
    </div>

    ${result.context?.exposure ? renderExposureSection(result.context.exposure) : ''}

    <div class="content">
      <div class="section">
        <h2>⚠️ Reachable Vulnerabilities (Action Required)</h2>
        ${
          reachable.length === 0
            ? '<p style="color: #28a745; font-size: 1.1em;">✅ No reachable vulnerabilities found!</p>'
            : reachable.map((v) => renderVulnerability(v)).join('')
        }
      </div>

      <div class="section">
        <h2>ℹ️ Not Reachable Vulnerabilities</h2>
        ${
          notReachable.length === 0
            ? '<p style="color: #666;">No non-reachable vulnerabilities.</p>'
            : notReachable.map((v) => renderVulnerability(v)).join('')
        }
      </div>

      <div class="section">
        <h2>📋 Next Steps</h2>
        <ol>
          <li>Review reachable vulnerabilities above</li>
          <li>Prioritize by severity and effort estimate</li>
          <li>Apply recommended patches or code changes</li>
          <li>Re-run analysis to confirm remediation</li>
          <li>Integrate VRA into CI/CD for continuous monitoring</li>
        </ol>
      </div>
    </div>

    <div class="footer">
      <p>📊 Report generated by VRA - Vulnerability Reachability Analyzer</p>
      <p>${new Date().toLocaleString()}</p>
    </div>
  </div>
</body>
</html>`;
}

function renderExposureSection(exposure: any): string {
  const isInternetFacing = exposure.is_internet_facing ? 'YES - Publicly Accessible' : 'NO - Internal Only';
  const statusClass = exposure.is_internet_facing ? 'internet-facing' : 'internal-only';
  const statusIcon = exposure.is_internet_facing ? '🌐' : '🔒';

  let detectionMethodsHtml = '';
  if (exposure.detection_methods && Array.isArray(exposure.detection_methods)) {
    detectionMethodsHtml = exposure.detection_methods
      .map((method: string) => `<span class="detection-method">${method}</span>`)
      .join('');
  }

  let endpointsHtml = '';
  if (exposure.verified_endpoints && Array.isArray(exposure.verified_endpoints)) {
    endpointsHtml = exposure.verified_endpoints
      .map(
        (endpoint: any) =>
          `<div class="endpoint-item">${endpoint.url} (${endpoint.method})</div>`,
      )
      .join('');
  }

  let dnsRecordsHtml = '';
  if (exposure.dns_records) {
    const records = exposure.dns_records;
    const aRecords = records.a_records ? records.a_records.join(', ') : 'None';
    const aaaaRecords = records.aaaa_records ? records.aaaa_records.join(', ') : 'None';
    dnsRecordsHtml = `
      <p><strong>A Records:</strong> ${aRecords}</p>
      <p><strong>AAAA Records:</strong> ${aaaaRecords}</p>
    `;
  }

  let sslHtml = '';
  if (exposure.ssl_certificate) {
    const cert = exposure.ssl_certificate;
    sslHtml = `
      <p><strong>Subject:</strong> ${cert.subject || 'N/A'}</p>
      <p><strong>Issuer:</strong> ${cert.issuer || 'N/A'}</p>
      <p><strong>Valid From:</strong> ${cert.valid_from || 'N/A'}</p>
      <p><strong>Valid To:</strong> ${cert.valid_to || 'N/A'}</p>
      <p><strong>Self-Signed:</strong> ${cert.is_self_signed ? 'Yes ⚠️' : 'No ✓'}</p>
    `;
  }

  let cdnHtml = '';
  if (exposure.cdn_info && exposure.cdn_info.detected) {
    cdnHtml = `<p><strong>CDN Provider:</strong> ${exposure.cdn_info.provider || 'Detected'}</p>`;
  }

  return `
    <div class="exposure-section">
      <h3>${statusIcon} Internet-Facing Exposure Detection</h3>

      <div class="exposure-status">
        <div class="exposure-status-card ${statusClass}">
          <div class="status-label">Internet-Facing Status</div>
          <div class="status-value">${isInternetFacing}</div>
        </div>
        <div class="exposure-status-card">
          <div class="status-label">Detection Confidence</div>
          <div class="status-value">
            <div class="confidence-bar">
              <div class="confidence-fill" style="width: ${exposure.detection_confidence || 0}%">
                ${exposure.detection_confidence || 0}%
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="exposure-details">
        <div class="exposure-detail-box">
          <h4>🔍 Detection Methods</h4>
          ${detectionMethodsHtml || '<p>No detection methods used</p>'}
        </div>

        ${
          exposure.verified_endpoints && exposure.verified_endpoints.length > 0
            ? `<div class="exposure-detail-box">
          <h4>🌐 Verified Endpoints</h4>
          ${endpointsHtml}
        </div>`
            : ''
        }

        ${
          exposure.dns_records
            ? `<div class="exposure-detail-box">
          <h4>📡 DNS Records</h4>
          ${dnsRecordsHtml}
        </div>`
            : ''
        }

        ${
          exposure.ssl_certificate
            ? `<div class="exposure-detail-box">
          <h4>🔐 SSL Certificate</h4>
          ${sslHtml}
        </div>`
            : ''
        }

        ${
          cdnHtml
            ? `<div class="exposure-detail-box">
          <h4>☁️ CDN Information</h4>
          ${cdnHtml}
        </div>`
            : ''
        }
      </div>

      ${
        exposure.verification_timestamp
          ? `<p style="margin-top: 15px; color: #666; font-size: 0.9em;">
        ⏰ Verification completed: ${new Date(exposure.verification_timestamp).toLocaleString()}
      </p>`
          : ''
      }
    </div>
  `;
}

function renderVulnerability(vuln: any): string {
  const severityClass = vuln.vulnerability.severity.toLowerCase();
  const typeClass = vuln.remediation.type.toLowerCase();

  return `
    <div class="vulnerability ${severityClass}">
      <div class="vuln-header">
        <span class="vuln-id">${vuln.vulnerability.cve_id} - ${vuln.vulnerability.package}@${vuln.vulnerability.current_version}</span>
        <span class="severity ${severityClass}">${vuln.vulnerability.severity}</span>
      </div>
      <div class="vuln-details">
        <p><strong>📌 Description:</strong> ${vuln.vulnerability.affected_versions.join(', ')}</p>
        <p><strong>🎯 Confidence:</strong> ${vuln.confidence}%</p>
        ${vuln.call_chain ? `<p><strong>🔗 Call Chain:</strong> ${vuln.call_chain.entry_point} → ${vuln.call_chain.path.join(' → ')}</p>` : ''}
        ${vuln.reason ? `<p><strong>📝 Reason:</strong> ${escapeHtml(vuln.reason)}</p>` : ''}

        <div class="remediation-section">
          <span class="remediation-type ${typeClass}">${vuln.remediation.type}</span>
          <h4>💡 Remediation</h4>
          <p>${escapeHtml(vuln.remediation.description)}</p>
          ${vuln.remediation.required_version ? `<p><strong>Target version:</strong> ${escapeHtml(vuln.remediation.required_version)}</p>` : ''}
          ${vuln.remediation.breaking_changes !== undefined ? `<p><strong>Breaking changes:</strong> ${vuln.remediation.breaking_changes ? 'Yes ⚠️' : 'No ✓'}</p>` : ''}
          ${
            vuln.remediation.changes_needed && vuln.remediation.changes_needed.length > 0
              ? `
            <p><strong>Code changes needed:</strong></p>
            <ul>
              ${vuln.remediation.changes_needed.map((c: string) => `<li>${escapeHtml(c)}</li>`).join('')}
            </ul>
          `
              : ''
          }
          ${vuln.remediation.action ? `<p><strong>Action:</strong> <code>${escapeHtml(vuln.remediation.action)}</code></p>` : ''}
          ${vuln.remediation.effort_estimate ? `<p><strong>⏱️ Effort:</strong> ${escapeHtml(vuln.remediation.effort_estimate)}</p>` : ''}
          ${vuln.remediation.notes ? `<p><strong>Notes:</strong> ${escapeHtml(vuln.remediation.notes)}</p>` : ''}
        </div>
      </div>
    </div>
  `;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
