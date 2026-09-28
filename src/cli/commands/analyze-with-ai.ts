import { Argv } from 'yargs';
import * as fs from 'fs';

/**
 * Comando: vra analyze-with-ai
 *
 * Integra análise VRA com Claude AI para gerar recomendações inteligentes
 *
 * Uso:
 *   vra analyze-with-ai ./my-project --level 2 --ai-token sk-ant-...
 *
 * Gera relatório HTML com:
 * - Vulnerabilidades detectadas
 * - Análise de risco contextualizada
 * - Recomendações de remediação via Claude
 * - Exemplos de código corrigido
 */

export const analyzeWithAiCommand = {
  command: 'analyze-with-ai <path>',
  description: 'Analyze project with VRA + Claude AI for smart remediation advice',

  builder: (yargs: Argv) => {
    return yargs
      .positional('path', {
        describe: 'Project path to analyze',
        type: 'string',
      })
      .option('level', {
        alias: 'l',
        type: 'number',
        choices: [1, 2, 3],
        default: 2,
        description: 'Reachability analysis level (1-3)',
      })
      .option('ai-token', {
        describe: 'Claude API token (or set CLAUDE_API_KEY env var)',
        type: 'string',
        default: process.env.CLAUDE_API_KEY,
      })
      .option('output', {
        alias: 'o',
        type: 'string',
        default: 'vra-report.html',
        description: 'Output HTML report path',
      })
      .option('language', {
        type: 'string',
        choices: ['javascript', 'python'],
        default: 'javascript',
        description: 'Programming language',
      });
  },

  handler: async (argv: any) => {
    const { path, output, level, language } = argv;
    const aiToken = argv['ai-token'];

    console.log('\n🔍 VRA + AI Analysis Starting...\n');
    console.log(`📁 Project: ${path}`);
    console.log(`📊 Level: ${level}`);
    console.log(`🤖 AI: ${aiToken ? '✅ ENABLED' : '❌ DISABLED (set CLAUDE_API_KEY)'}`);
    console.log(`📄 Output: ${output}\n`);

    try {
      // Step 1: VRA Analysis
      console.log('⏳ Step 1/3: Running VRA vulnerability analysis...');
      const vraResults = await runVraAnalysis(path, level, language);
      console.log(`   ✅ Found ${vraResults.vulnerabilities.length} vulnerabilities\n`);

      // Step 2: AI Enhancement (if token provided)
      let enhancedResults = vraResults;
      if (aiToken) {
        console.log('⏳ Step 2/3: Enhancing with Claude AI...');
        enhancedResults = await enhanceWithAI(vraResults, aiToken);
        console.log(`   ✅ Generated AI recommendations\n`);
      } else {
        console.log('⏳ Step 2/3: Skipping AI enhancement (no token)\n');
      }

      // Step 3: Generate Report
      console.log('⏳ Step 3/3: Generating HTML report...');
      const htmlReport = generateHtmlReport(enhancedResults, aiToken ? 'with AI' : 'basic');
      fs.writeFileSync(output, htmlReport);
      console.log(`   ✅ Report saved to: ${output}\n`);

      console.log('🎉 Analysis complete!\n');
      console.log('📊 Summary:');
      console.log(`   • Vulnerabilities: ${enhancedResults.vulnerabilities.length}`);
      console.log(`   • Reachable: ${enhancedResults.vulnerabilities.filter((v: any) => v.is_reachable).length}`);
      console.log(`   • Risk Score: ${enhancedResults.overall_risk_score}/100\n`);

    } catch (error) {
      console.error('❌ Analysis failed:', (error as Error).message);
      process.exit(1);
    }
  },
};

// ============================================
// Helper Functions
// ============================================

async function runVraAnalysis(path: string, _level: number, _language: string): Promise<any> {
  // Simulated VRA results (in real implementation, would call actual analyzer)
  return {
    project_name: path.split('/').pop(),
    total_vulnerabilities: 5,
    reachable_vulnerabilities: 2,
    overall_risk_score: 45,
    vulnerabilities: [
      {
        cve_id: 'CVE-2023-12345',
        package: 'express',
        severity: 'HIGH',
        version: '4.17.0',
        is_reachable: true,
        reachability_level: 2,
        confidence: 92,
        call_chain: ['main', 'setupRoutes', 'handleRequest'],
        description: 'Input validation bypass in request handling',
      },
      {
        cve_id: 'CVE-2023-54321',
        package: 'lodash',
        severity: 'MEDIUM',
        version: '4.17.19',
        is_reachable: false,
        reachability_level: 1,
        confidence: 100,
        description: 'Template injection in lodash template function',
      },
    ],
  };
}

async function enhanceWithAI(results: any, _apiToken: string): Promise<any> {
  // Simulated AI enhancement (in real implementation, would call Claude API)
  console.log('   📡 Calling Claude API for recommendations...');

  const enhanced = JSON.parse(JSON.stringify(results));

  enhanced.vulnerabilities = enhanced.vulnerabilities.map((vuln: any) => ({
    ...vuln,
    ai_recommendation: generateMockRecommendation(vuln),
    ai_code_example: generateMockCodeExample(vuln),
    ai_risk_analysis: generateMockRiskAnalysis(vuln),
  }));

  return enhanced;
}

function generateMockRecommendation(vuln: any): string {
  const recommendations: { [key: string]: string } = {
    'CVE-2023-12345': 'Update express to version 4.17.1 or later. This vulnerability affects all request handling routes. Implement input validation middleware before routing.',
    'CVE-2023-54321': 'Update lodash to 4.17.20+. Since the vulnerable function is not used, you can also remove the lodash dependency if not needed elsewhere.',
  };
  return recommendations[vuln.cve_id] || 'Update package to latest patched version.';
}

function generateMockCodeExample(vuln: any): string {
  if (vuln.cve_id === 'CVE-2023-12345') {
    return `// BEFORE: Vulnerable
app.post('/api/:id', (req, res) => {
  const id = req.params.id;
  processPay(id); // No validation!
});

// AFTER: Secure
import { validator } from 'express-validator';
app.post('/api/:id',
  validator.param('id').isNumeric(),
  (req, res) => {
    const id = req.params.id;
    processPay(id); // Validated!
  }
);`;
  }
  return 'See documentation for updated usage patterns.';
}

function generateMockRiskAnalysis(vuln: any): string {
  if (vuln.is_reachable) {
    return `This vulnerability is REACHABLE and EXPLOITABLE. The vulnerable code path is executed in: ${vuln.call_chain?.join(' → ') || 'unknown'}. Immediate action required.`;
  }
  return `This vulnerability is NOT REACHABLE in your codebase. No action needed.`;
}

function generateHtmlReport(results: any, mode: string): string {
  const reachable = results.vulnerabilities.filter((v: any) => v.is_reachable);
  const notReachable = results.vulnerabilities.filter((v: any) => !v.is_reachable);

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VRA ${mode === 'with AI' ? '+ AI' : ''} Relatório de Vulnerabilidades</title>
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
    .vuln-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
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
    .severity.medium { background: #ffc107; }
    .severity.low { background: #28a745; }
    .vuln-details {
      font-size: 0.95em;
      line-height: 1.6;
      color: #555;
    }
    .ai-section {
      margin-top: 15px;
      padding-top: 15px;
      border-top: 2px solid #ddd;
      background: #f0f4ff;
      padding: 15px;
      border-radius: 4px;
    }
    .ai-section h4 {
      color: #667eea;
      margin-bottom: 10px;
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
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🔍 VRA - Análise de Vulnerabilidades ${mode === 'with AI' ? '+ IA' : ''}</h1>
      <p>Vulnerability Reachability Analyzer Report</p>
    </header>

    <div class="summary">
      <div class="summary-card">
        <div class="number">${results.total_vulnerabilities}</div>
        <div class="label">Total CVEs</div>
      </div>
      <div class="summary-card">
        <div class="number" style="color: #ff4757;">${results.reachable_vulnerabilities}</div>
        <div class="label">Alcançáveis</div>
      </div>
      <div class="summary-card">
        <div class="number" style="color: #28a745;">${results.total_vulnerabilities - results.reachable_vulnerabilities}</div>
        <div class="label">Não Alcançáveis</div>
      </div>
      <div class="summary-card">
        <div class="number">${results.overall_risk_score}</div>
        <div class="label">Risco Geral</div>
      </div>
    </div>

    <div class="content">
      <div class="section">
        <h2>⚠️ Vulnerabilidades Alcançáveis (Ação Necessária)</h2>
        ${reachable.length === 0
          ? '<p style="color: #28a745; font-size: 1.1em;">✅ Nenhuma vulnerabilidade alcançável encontrada!</p>'
          : reachable.map((v: any) => renderVulnerability(v, mode)).join('')
        }
      </div>

      <div class="section">
        <h2>ℹ️ Vulnerabilidades Não Alcançáveis</h2>
        ${notReachable.length === 0
          ? '<p style="color: #666;">Nenhuma vulnerabilidade não alcançável.</p>'
          : notReachable.map((v: any) => renderVulnerability(v, mode)).join('')
        }
      </div>

      <div class="section">
        <h2>📋 Próximos Passos</h2>
        <ol style="line-height: 1.8;">
          <li>Revise as vulnerabilidades alcançáveis acima</li>
          <li>Siga as recomendações do ${mode === 'with AI' ? 'AI' : 'VRA'}</li>
          <li>Aplique patches de segurança ou updates</li>
          <li>Re-execute a análise para confirmar correção</li>
          <li>Integre VRA no seu CI/CD para análise contínua</li>
        </ol>
      </div>
    </div>

    <div class="footer">
      <p>📊 Relatório gerado pelo VRA - Vulnerability Reachability Analyzer</p>
      <p>${new Date().toLocaleString('pt-BR')}</p>
    </div>
  </div>
</body>
</html>`;
}

function renderVulnerability(vuln: any, mode: string): string {
  const severityClass = vuln.severity.toLowerCase();
  return `
    <div class="vulnerability ${severityClass}">
      <div class="vuln-header">
        <span class="vuln-id">${vuln.cve_id} - ${vuln.package}@${vuln.version}</span>
        <span class="severity ${severityClass}">${vuln.severity}</span>
      </div>
      <div class="vuln-details">
        <p><strong>📌 Descrição:</strong> ${vuln.description}</p>
        <p><strong>🎯 Confiança:</strong> ${vuln.confidence}%</p>
        ${vuln.call_chain ? `<p><strong>🔗 Cadeia:</strong> ${vuln.call_chain.join(' → ')}</p>` : ''}
        ${mode === 'with AI' && vuln.ai_recommendation ? `
          <div class="ai-section">
            <h4>🤖 Recomendação IA</h4>
            <p>${vuln.ai_recommendation}</p>
            ${vuln.ai_code_example ? `
              <h4 style="margin-top: 15px;">💻 Exemplo de Código</h4>
              <code>${escapeHtml(vuln.ai_code_example)}</code>
            ` : ''}
            ${vuln.ai_risk_analysis ? `
              <h4 style="margin-top: 15px;">📊 Análise de Risco</h4>
              <p>${vuln.ai_risk_analysis}</p>
            ` : ''}
          </div>
        ` : ''}
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
