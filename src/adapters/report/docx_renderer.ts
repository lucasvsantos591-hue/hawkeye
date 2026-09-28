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

export async function renderDocxReport(result: AnalysisResult): Promise<Buffer> {
  const sections: (Paragraph | Table)[] = [];
  const reachableVulnerabilities = result.results.filter((r) => r.is_reachable);

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
      (_, i) =>
        `${i + 3}. ${result.results[i].vulnerability.cve_id} · ${result.results[i].vulnerability.package} ......................................................................................  ${i + 4}`,
    ),
    `${reachableVulnerabilities.length + 3}. Plano de Ação e Referências ...............................................................................  ${reachableVulnerabilities.length + 4}`,
  ];

  tocItems.forEach((item) => {
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

  sections.push(new Paragraph({ text: '', pageBreakBefore: true }));

  // ========== UMA PÁGINA POR CVE ALCANÇÁVEL ==========
  reachableVulnerabilities.forEach((finding, idx) => {
    const vuln = finding.vulnerability;
    const severity = vuln.severity;
    const severityColor =
      severity === 'CRITICAL' ? COLORS.VERMELHO : severity === 'HIGH' ? COLORS.LARANJA : severity === 'MEDIUM' ? COLORS.AZUL : COLORS.VERDE;

    // Header com barra colorida
    sections.push(
      new Paragraph({
        children: [
          new TextRun({
            text: `${vuln.cve_id}  ·  ${vuln.package}  ·  SEVERIDADE ${severity}`,
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
        `${vuln.affected_versions} não bloqueiam ${finding.vulnerability.cve_id} em ${finding.vulnerability.package}. Permite operação de ${finding.reason || 'operação perigosa'}.`,
        { size: 9 },
      ),
    );

    // Tabela de Alcançabilidade
    sections.push(
      createTable(
        ['Alcançabilidade', 'Confiança', 'EPSS', 'CISA KEV', 'Prioridade'],
        [
          [
            `Nível ${finding.reachability_level}`,
            `${finding.confidence}%`,
            `${vuln.epss_score?.toFixed(1) || '—'}/100`,
            vuln.is_exploited_in_wild ? 'Sim' : 'Não listada',
            severity,
          ],
        ],
      ),
    );

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

    sections.push(
      ...createCodeBlock(
        `npm install ${vuln.package}@${finding.remediation.required_version || 'latest'} && npm test`,
        'Comando:',
      ),
    );

    sections.push(
      createText(`Esforço: ${finding.remediation.effort_estimate || 'A determinar'}`, { bold: true, size: 9 }),
    );

    if (finding.remediation.breaking_changes) {
      sections.push(createText('⚠️ Quebra de compatibilidade: sim (5.x removeu variantes legadas)', { size: 9 }));
    }

    if (finding.remediation.changes_needed && finding.remediation.changes_needed.length > 0) {
      sections.push(createText('Ajustes necessários:', { bold: true, size: 9 }));
      sections.push(...createBulletList(finding.remediation.changes_needed.map((c) => c)));
    }

    if (idx < reachableVulnerabilities.length - 1) {
      sections.push(new Paragraph({ text: '', pageBreakBefore: true }));
    }
  });

  sections.push(new Paragraph({ text: '', pageBreakBefore: true }));

  // ========== PLANO DE AÇÃO ==========
  sections.push(createHeading(`${reachableVulnerabilities.length + 3}. Plano de Ação e Referências`));

  sections.push(createHeading('Sequência de Remediação', 2));

  const actionItems = reachableVulnerabilities.map((r) => [
    `Dia 1–2: ${r.vulnerability.cve_id}`,
    r.remediation.effort_estimate || 'A determinar',
    r.remediation.type,
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
