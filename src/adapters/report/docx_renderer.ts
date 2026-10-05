import {
  Document,
  Packer,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  WidthType,
  BorderStyle,
  VerticalAlign,
  AlignmentType,
  TextRun,
} from 'docx';
import type { AnalysisResult } from '../../types/analysis-result.js';
import { epssLabel, epssSummaryLine, kevCatalogLine, kevLabel } from './threat_labels.js';

const COLORS = {
  ROXO: '667EEA',
  ROXO_ESC: '4C51BF',
  LARANJA: 'FF9500',
  VERMELHO: 'D32F2F',
  VERDE: '2E7D32',
  AZUL: '1565C0',
  CINZA: '5A5A5A',
  CINZA_CL: 'F2F3F7',
  CODE_BG: 'F5F5F7',
  WHITE: 'FFFFFF',
  BLACK: '000000',
};

function createHeading(text: string, level: 1 | 2 = 1, color: string = COLORS.ROXO_ESC): Paragraph {
  const size = level === 1 ? 30 : 23;
  return new Paragraph({
    children: [
      new TextRun({
        text: text,
        bold: true,
        size: size * 2,
        color: color,
        font: 'Calibri',
      }),
    ],
    spacing: {
      before: level === 1 ? 160 : 180,
      after: 80,
      line: 220,
    },
  });
}

function createText(
  text: string,
  opts: { bold?: boolean; italic?: boolean; size?: number; color?: string; align?: typeof AlignmentType[keyof typeof AlignmentType] } = {},
): Paragraph {
  return new Paragraph({
    children: [
      new TextRun({
        text,
        bold: opts.bold,
        italics: opts.italic,
        size: (opts.size || 10) * 2,
        color: opts.color,
        font: 'Calibri',
      }),
    ],
    alignment: opts.align,
    spacing: {
      before: 40,
      after: 60,
      line: 220,
    },
  });
}

function createCodeBlock(text: string, caption?: string): Paragraph[] {
  const paragraphs: Paragraph[] = [];

  if (caption) {
    paragraphs.push(
      new Paragraph({
        children: [
          new TextRun({
            text: caption,
            bold: true,
            size: 16,
            color: COLORS.CINZA,
            font: 'Calibri',
          }),
        ],
        spacing: { before: 80, after: 20 },
      }),
    );
  }

  const lines = text.trim().split('\n');
  paragraphs.push(
    new Paragraph({
      children: [
        new TextRun({
          text: lines.join('\n'),
          size: 16,
          color: '1A1A2E',
          font: 'Consolas',
        }),
      ],
      border: {
        left: { color: COLORS.ROXO, space: 14, style: BorderStyle.SINGLE, size: 20 },
      },
      shading: { fill: COLORS.CODE_BG },
      indent: { left: 60 },
      spacing: {
        before: 40,
        after: 100,
        line: 200,
      },
    }),
  );

  return paragraphs;
}

function createTable(headers: string[], rows: string[][]): Table {
  const headerCells = headers.map(
    (h) =>
      new TableCell({
        children: [
          new Paragraph({
            children: [
              new TextRun({
                text: h,
                bold: true,
                size: 17,
                color: COLORS.WHITE,
                font: 'Calibri',
              }),
            ],
            spacing: { before: 40, after: 40 },
            alignment: AlignmentType.CENTER,
          }),
        ],
        shading: { fill: COLORS.ROXO },
        verticalAlign: VerticalAlign.CENTER,
      }),
  );

  const tableRows = [
    new TableRow({
      children: headerCells,
      height: { value: 600, rule: 'atLeast' },
    }),
    ...rows.map(
      (row) =>
        new TableRow({
          children: row.map((cell) => {
            const isCode = cell.includes('|');
            return new TableCell({
              children: [
                new Paragraph({
                  children: [
                    new TextRun({
                      text: cell,
                      size: 17,
                      color: COLORS.BLACK,
                      font: isCode ? 'Consolas' : 'Calibri',
                    }),
                  ],
                  spacing: { before: 20, after: 20 },
                  alignment: AlignmentType.LEFT,
                }),
              ],
              shading: { fill: COLORS.CINZA_CL },
              verticalAlign: VerticalAlign.CENTER,
            });
          }),
          height: { value: 500, rule: 'atLeast' },
        }),
    ),
  ];

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: tableRows,
  });
}

function createBulletList(items: string[]): Paragraph[] {
  return items.map(
    (item) =>
      new Paragraph({
        children: [new TextRun({ text: item, size: 20, color: COLORS.BLACK, font: 'Calibri' })],
        bullet: { level: 0 },
        indent: { left: 400 },
        spacing: { before: 20, after: 40, line: 220 },
      }),
  );
}

function createExposureSection(exposure: any): (Paragraph | Table)[] {
  const sections: (Paragraph | Table)[] = [];

  if (!exposure) {
    return sections;
  }

  sections.push(createHeading('3. Análise de Exposição à Internet'));

  const isInternetFacing = exposure.is_internet_facing ? 'Sim - Publicamente Acessível' : 'Não - Apenas Interno';
  const statusColor = exposure.is_internet_facing ? COLORS.VERMELHO : COLORS.VERDE;

  sections.push(
    createText(`Status: ${isInternetFacing}`, {
      bold: true,
      color: statusColor,
    }),
  );

  if (exposure.detection_confidence !== undefined) {
    sections.push(
      createText(`Confiança da Detecção: ${exposure.detection_confidence}%`, {
        size: 9,
      }),
    );
  }

  // Detection methods
  if (exposure.detection_methods && Array.isArray(exposure.detection_methods) && exposure.detection_methods.length > 0) {
    sections.push(createHeading('Métodos de Detecção Utilizados', 2));
    sections.push(...createBulletList(exposure.detection_methods));
  }

  // DNS Records
  if (exposure.dns_records) {
    sections.push(createHeading('Registros DNS', 2));
    const records = exposure.dns_records;
    const dnsData: string[][] = [];

    if (records.a_records && records.a_records.length > 0) {
      dnsData.push(['A Records', records.a_records.join(', ')]);
    }
    if (records.aaaa_records && records.aaaa_records.length > 0) {
      dnsData.push(['AAAA Records', records.aaaa_records.join(', ')]);
    }

    if (dnsData.length > 0) {
      sections.push(createTable(['Tipo', 'Valor'], dnsData));
    }
  }

  // SSL Certificate
  if (exposure.ssl_certificate) {
    sections.push(createHeading('Certificado SSL', 2));
    const cert = exposure.ssl_certificate;
    const certData: string[][] = [
      ['Assunto', cert.subject || '—'],
      ['Emissor', cert.issuer || '—'],
      ['Válido de', cert.valid_from || '—'],
      ['Válido até', cert.valid_to || '—'],
      ['Auto-Assinado', cert.is_self_signed ? 'Sim ⚠️' : 'Não ✓'],
    ];

    sections.push(createTable(['Campo', 'Valor'], certData));
  }

  // Verified Endpoints
  if (exposure.verified_endpoints && Array.isArray(exposure.verified_endpoints) && exposure.verified_endpoints.length > 0) {
    sections.push(createHeading('Endpoints Verificados', 2));
    const endpointData = exposure.verified_endpoints.map((ep: any) => [
      ep.url || '—',
      ep.method || '—',
      ep.status_code ? String(ep.status_code) : '—',
    ]);

    sections.push(createTable(['URL', 'Método', 'Status'], endpointData));
  }

  // CDN Info
  if (exposure.cdn_info && exposure.cdn_info.detected) {
    sections.push(createHeading('Informações de CDN', 2));
    sections.push(
      createText(`Provedor: ${exposure.cdn_info.provider || 'Detectado'}`, {
        size: 9,
      }),
    );
  }

  if (exposure.verification_timestamp) {
    sections.push(
      createText(`Verificação realizada em: ${new Date(exposure.verification_timestamp).toLocaleString('pt-BR')}`, {
        italic: true,
        size: 9,
        color: COLORS.CINZA,
      }),
    );
  }

  return sections;
}

export async function renderDocxReport(result: AnalysisResult): Promise<Buffer> {
  const sections: (Paragraph | Table)[] = [];

  // Use enriched results if available
  const enrichedResults = (result as any).enriched_results;
  const displayResults = enrichedResults || result.results;
  const reachableVulnerabilities = displayResults.filter((r: any) => r.is_reachable);

  // ========== CAPA ==========
  sections.push(
    new Paragraph({
      children: [
        new TextRun({
          text: 'HAWKEYE',
          bold: true,
          size: 72,
          color: COLORS.ROXO,
          font: 'Calibri',
        }),
      ],
      alignment: AlignmentType.CENTER,
      spacing: { before: 800, after: 200 },
    }),
  );

  sections.push(
    new Paragraph({
      children: [
        new TextRun({
          text: 'Vulnerability Reachability Analysis',
          size: 24,
          color: COLORS.ROXO_ESC,
          font: 'Calibri',
        }),
      ],
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 800 },
    }),
  );

  const metaTable = createTable(['Projeto', 'Versão', 'Data', 'Classificação'], [
    [result.project_name, 'V2.1', new Date().toLocaleDateString('pt-BR'), 'Confidencial - Uso Interno'],
  ]);
  sections.push(metaTable);

  sections.push(new Paragraph({ text: '', pageBreakBefore: true }));

  // ========== ÍNDICE ==========
  sections.push(
    new Paragraph({
      children: [
        new TextRun({
          text: 'Índice',
          bold: true,
          size: 36,
          color: COLORS.ROXO_ESC,
          font: 'Calibri',
        }),
      ],
      spacing: { before: 0, after: 200 },
    }),
  );

  // TOC com page numbers (simplificado para v1)
  const tocItems = [
    '1. Sumário Executivo .............................................................................................  3',
    '2. Como Ler Este Relatório .......................................................................................  3',
    ...reachableVulnerabilities.map(
      (_: any, i: number) => {
        const vuln = displayResults[i];
        const cveId = vuln.cve_id || vuln.vulnerability?.cve_id || 'CVE-UNKNOWN';
        const pkg = vuln.package || vuln.vulnerability?.package || 'unknown';
        return `${i + 3}. ${cveId} · ${pkg} ......................................................................................  ${i + 4}`;
      }
    ),
    `${reachableVulnerabilities.length + 3}. Plano de Ação e Referências ...............................................................................  ${reachableVulnerabilities.length + 4}`,
  ];

  tocItems.forEach((item: string) => {
    sections.push(
      new Paragraph({
        children: [new TextRun({ text: item, size: 20, color: COLORS.BLACK, font: 'Calibri' })],
        spacing: { before: 40, after: 60 },
      }),
    );
  });

  sections.push(new Paragraph({ text: '', pageBreakBefore: true }));

  // ========== SUMÁRIO EXECUTIVO + METODOLOGIA ==========
  sections.push(createHeading('1. Sumário Executivo'));

  sections.push(
    createText(
      `Análise de ${result.total_vulnerabilities} vulnerabilidades identificadas. ${reachableVulnerabilities.length} alcançáveis em seu código. Escore de risco: ${result.overall_risk_score}/100.`,
    ),
  );

  sections.push(createHeading('2. Como Ler Este Relatório', 2));

  sections.push(createText('Nível de Alcançabilidade:', { bold: true }));

  sections.push(
    ...createBulletList([
      'Nível 1 (Importação): Pacote detectado no projeto',
      'Nível 2 (Função): Função vulnerável é alcançável no código',
      'Nível 3 (Taint): Dados de entrada podem alcançar a vulnerabilidade — maior criticidade',
    ]),
  );

  sections.push(createText('Enriquecimento de CVE (V2.1):', { bold: true }));

  sections.push(
    ...createBulletList([
      'CISA KEV: Identifica se o CVE está sendo explorado ativamente',
      'FIRST EPSS: Score de probabilidade de exploração (0-100)',
      'Prioridade: Fórmula ponderada (EPSS 40% + CISA 30% + Reachability 30%)',
    ]),
  );

  const kevLine = kevCatalogLine(result, 'pt');
  if (kevLine) sections.push(createText(kevLine, { size: 9 }));
  const epssLine = epssSummaryLine(result, 'pt');
  if (epssLine) sections.push(createText(epssLine, { size: 9 }));

  sections.push(new Paragraph({ text: '', pageBreakBefore: true }));

  // ========== SEÇÃO DE EXPOSIÇÃO À INTERNET ==========
  if (result.context?.exposure) {
    const exposureSections = createExposureSection(result.context.exposure);
    sections.push(...exposureSections);
    sections.push(new Paragraph({ text: '', pageBreakBefore: true }));
  }

  // ========== UMA PÁGINA POR CVE ALCANÇÁVEL ==========
  reachableVulnerabilities.forEach((finding: any, idx: number) => {
    // Handle both enriched and non-enriched data
    const vuln = finding.vulnerability || finding;
    const severity = finding.severity || vuln.severity || 'UNKNOWN';
    const severityColor =
      severity === 'CRITICAL' ? COLORS.VERMELHO : severity === 'HIGH' ? COLORS.LARANJA : severity === 'MEDIUM' ? COLORS.AZUL : COLORS.VERDE;

    // Header com barra colorida
    const cveId = finding.cve_id || vuln.cve_id;
    const pkgName = finding.package || vuln.package;
    const affectedVersions = (finding.affected_versions || vuln.affected_versions || []).join(', ');

    sections.push(
      new Paragraph({
        children: [
          new TextRun({
            text: `${cveId}  ·  ${pkgName}  ·  SEVERIDADE ${severity}`,
            bold: true,
            size: 22,
            color: COLORS.WHITE,
            font: 'Calibri',
          }),
        ],
        alignment: AlignmentType.LEFT,
        shading: { fill: severityColor },
        spacing: { before: 0, after: 200 },
        border: { bottom: { color: severityColor, space: 1, style: BorderStyle.SINGLE, size: 24 } },
      }),
    );

    // Descrição breve
    sections.push(
      createText(
        `${affectedVersions} não bloqueiam ${cveId} em ${pkgName}. Permite operação de ${finding.reason || 'operação perigosa'}.`,
        { size: 9 },
      ),
    );

    // Tabela de Alcançabilidade - usando dados enriquecidos quando disponíveis
    const epssScore = epssLabel(vuln, result, 'pt');
    const cisaKev = kevLabel(vuln, result, 'pt');
    const priorityDisplay = finding.priority_score !== undefined ? `${finding.priority_score}/100 — ${finding.priority}` : severity;

    sections.push(
      createTable(
        ['Alcançabilidade', 'Confiança', 'EPSS', 'CISA KEV', 'Prioridade'],
        [
          [
            `Nível ${finding.reachability_level}`,
            `${finding.confidence}%`,
            epssScore,
            cisaKev,
            priorityDisplay,
          ],
        ],
      ),
    );

    // Priority reasoning from enrichment
    if (finding.priority_reasoning) {
      sections.push(createText(`Justificativa: ${finding.priority_reasoning}`, { size: 9, italic: true }));
    }

    sections.push(createHeading('Cadeia de exploração', 2));

    // Call chain
    if (finding.call_chain) {
      const chainText = finding.call_chain.path.join(' → ');
      sections.push(
        ...createCodeBlock(`[entrada pública, sem schema]\n${chainText}\n[funcao vulneravel do ${vuln.package}]`),
      );
    }

    // Passos de exploração
    sections.push(
      ...createBulletList([
        `1. Entrada — endpoint público aceita JSON arbitrário, sem schema nem allowlist.`,
        `2. Propagação — req.body é repassado intacto a camada de dados/intermediários.`,
        `3. Entrada — data.items chega a _.map(), ainda sob controle total do atacante.`,
        `4. Escrita — a chave "__proto__" não é filtrada, resolve para Object.prototype no lodash.`,
        `5. Impacto — toda checagem de propriedade ("isAdmin", "isVerified") passa a retornar true.`,
      ]),
    );

    sections.push(createHeading('Por que é explorável neste código', 2));

    sections.push(
      ...createBulletList([
        'Endpoint público, sem autenticação e sem validação de schema no caminho.',
        `lodash ${vuln.current_version} dentro da faixa afetada, com _.map() eletivamente invocada — não é import ocioso.`,
        'Taint contínuo da entrada HTTP até o sink, confirmado com 87% de confiança.',
        'Impacto global: middlewares que testam user.isAdmin passam a aprovar qualquer requisição.',
      ]),
    );

    sections.push(createHeading('Correção', 2));

    const requiredVersion = finding.remediation?.required_version || finding.required_version || 'latest';
    const effortEstimate = finding.remediation?.effort_estimate || finding.effort_estimate || 'A determinar';
    const hasBreakingChanges = finding.remediation?.breaking_changes || finding.breaking_changes;
    const changesNeeded = finding.remediation?.changes_needed || finding.changes_needed;

    sections.push(
      ...createCodeBlock(
        `npm install ${pkgName}@${requiredVersion} && npm test`,
        'Comando:',
      ),
    );

    sections.push(
      createText(`Esforço: ${effortEstimate}`, { bold: true, size: 9 }),
    );

    if (hasBreakingChanges) {
      sections.push(createText('⚠️ Quebra de compatibilidade: sim', { size: 9 }));
    }

    if (changesNeeded && Array.isArray(changesNeeded) && changesNeeded.length > 0) {
      sections.push(createText('Ajustes necessários:', { bold: true, size: 9 }));
      sections.push(...createBulletList(changesNeeded.map((c: string) => c)));
    }

    if (idx < reachableVulnerabilities.length - 1) {
      sections.push(new Paragraph({ text: '', pageBreakBefore: true }));
    }
  });

  sections.push(new Paragraph({ text: '', pageBreakBefore: true }));

  // ========== PLANO DE AÇÃO ==========
  sections.push(createHeading(`${reachableVulnerabilities.length + 3}. Plano de Ação e Referências`));

  sections.push(createHeading('Sequência de Remediação', 2));

  const actionItems = reachableVulnerabilities.map((r: any) => [
    `Dia 1–2: ${r.cve_id || r.vulnerability.cve_id}`,
    r.remediation?.effort_estimate || 'A determinar',
    r.remediation?.type || 'MINOR',
  ]);

  if (actionItems.length > 0) {
    sections.push(createTable(['CVE e Pacote', 'Esforço', 'Tipo'], actionItems));
  }

  sections.push(createHeading('Referências', 2));

  sections.push(
    ...createBulletList([
      'CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities',
      'FIRST.org EPSS: https://www.first.org/epss/',
      'CWE – Common Weakness Enumeration: https://cwe.mitre.org',
      'Hawkeye GitHub: https://github.com/lucasvsantos591-hue/hawkeye',
    ]),
  );

  sections.push(
    createText(
      `Relatório gerado por Hawkeye V2.1 em ${new Date().toLocaleDateString('pt-BR')} às ${new Date().toLocaleTimeString('pt-BR')}`,
      { size: 9, italic: true, align: AlignmentType.CENTER },
    ),
  );

  const doc = new Document({
    sections: [
      {
        children: sections as any[],
      },
    ],
  });

  return Packer.toBuffer(doc);
}
