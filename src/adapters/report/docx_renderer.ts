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

  const displayResults = result.results;
  const reachableVulnerabilities = displayResults.filter(r => r.is_reachable);

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
    [result.project_name, `Hawkeye ${result.scan?.tool_version ?? ''}`.trim(), new Date().toLocaleDateString('pt-BR'), 'Confidencial - Uso Interno'],
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
      (finding, i) => {
        const cveId = finding.vulnerability.cve_id;
        const pkg = finding.vulnerability.package;
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
      'Nível 1 (Importação): o pacote é importado ou carregado pelo projeto',
      'Nível 2 (Uso): os nomes importados do pacote são usados no código; a função vulnerável em si não é identificada',
    ]),
  );

  sections.push(createText('Enriquecimento de CVE:', { bold: true }));

  sections.push(
    ...createBulletList([
      'CISA KEV: Identifica se o CVE está sendo explorado ativamente',
      'FIRST EPSS: Probabilidade (%) de exploração nos próximos 30 dias',
      'Prioridade: alcançável → CISA KEV → severidade → confiança → EPSS',
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

    // Descrição: só dados do advisory e do finding, nada inferido
    const fixed = vuln.fixed_version ? `corrigida em ${vuln.fixed_version}` : 'sem versão corrigida publicada';
    sections.push(
      createText(
        `${vuln.summary ? `${vuln.summary}. ` : ''}Versão instalada: ${vuln.current_version}` +
          `${affectedVersions ? ` (afetadas: ${affectedVersions})` : ''}; ${fixed}.`,
        { size: 9 },
      ),
    );

    const epssScore = epssLabel(vuln, result, 'pt');
    const cisaKev = kevLabel(vuln, result, 'pt');

    sections.push(
      createTable(
        ['Alcançabilidade', 'Confiança', 'EPSS', 'CISA KEV', 'Severidade'],
        [[`Nível ${finding.reachability_level}`, `${finding.confidence}%`, epssScore, cisaKev, severity]],
      ),
    );

    sections.push(createHeading('Por que é alcançável', 2));

    if (finding.reason) sections.push(createText(finding.reason, { size: 9 }));
    if (finding.call_chain) {
      sections.push(
        ...createCodeBlock(`${finding.call_chain.entry_point}\n${finding.call_chain.path.join(' → ')}`, 'Caminho:'),
      );
    }
    const sites: string[] = finding.evidence?.sites ?? [];
    if (sites.length) {
      sections.push(createText('Onde o código usa o pacote:', { bold: true, size: 9 }));
      sections.push(...createBulletList([...sites.slice(0, 5), ...(sites.length > 5 ? [`… e mais ${sites.length - 5}`] : [])]));
    }
    sections.push(
      createText(
        'O Hawkeye confirma que o pacote é usado pelo código, não que a função vulnerável é chamada: ' +
          'confira o advisory antes de descartar o risco.',
        { size: 9, italic: true },
      ),
    );

    sections.push(createHeading('Correção', 2));

    const remediation = finding.remediation ?? {};
    if (remediation.description) sections.push(createText(remediation.description, { size: 9 }));
    if (remediation.action) sections.push(...createCodeBlock(remediation.action, 'Comando:'));
    if (remediation.effort_estimate) {
      sections.push(createText(`Esforço: ${remediation.effort_estimate}`, { bold: true, size: 9 }));
    }
    if (remediation.breaking_changes) {
      sections.push(createText('⚠️ Quebra de compatibilidade provável (versão major)', { size: 9 }));
    }
    if (Array.isArray(remediation.changes_needed) && remediation.changes_needed.length > 0) {
      sections.push(createText('Ajustes necessários:', { bold: true, size: 9 }));
      sections.push(...createBulletList(remediation.changes_needed));
    }

    if (idx < reachableVulnerabilities.length - 1) {
      sections.push(new Paragraph({ text: '', pageBreakBefore: true }));
    }
  });

  sections.push(new Paragraph({ text: '', pageBreakBefore: true }));

  // ========== PLANO DE AÇÃO ==========
  sections.push(createHeading(`${reachableVulnerabilities.length + 3}. Plano de Ação e Referências`));

  sections.push(createHeading('Sequência de Remediação', 2));

  // Mesma ordem do relatório: alcançável → KEV → severidade → confiança → EPSS
  const actionItems = reachableVulnerabilities.map(r => [
    `${r.vulnerability.cve_id} · ${r.vulnerability.package}`,
    r.remediation.type,
    r.remediation.action ?? r.remediation.description,
  ]);

  if (actionItems.length > 0) {
    sections.push(createTable(['CVE e Pacote', 'Tipo', 'Ação'], actionItems));
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
      `Relatório gerado por Hawkeye${result.scan?.tool_version ? ` ${result.scan.tool_version}` : ''} em ${new Date().toLocaleDateString('pt-BR')} às ${new Date().toLocaleTimeString('pt-BR')}`,
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
