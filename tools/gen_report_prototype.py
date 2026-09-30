# -*- coding: utf-8 -*-
"""Hawkeye V2.1 - Relatorio executivo enxuto: 1 pagina por CVE."""
from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import (WD_ALIGN_PARAGRAPH, WD_BREAK,
                            WD_TAB_ALIGNMENT, WD_TAB_LEADER)
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import json, os

ROXO, ROXO_ESC = '667EEA', '4C51BF'
LARANJA, VERMELHO, VERDE, AZUL = 'FF9500', 'D32F2F', '2E7D32', '1565C0'
CINZA, CINZA_CL, CODE_BG = '5A5A5A', 'F2F3F7', 'F5F5F7'

def C(h): return RGBColor.from_string(h)

HERE = os.path.dirname(os.path.abspath(__file__))
PAGEMAP = json.load(open(os.path.join(HERE, 'pagemap2.json'), encoding='utf-8')) \
          if os.path.exists(os.path.join(HERE, 'pagemap2.json')) else {}

EM = '—'
SUMARIO = [
    '1. Sumário Executivo',
    '2. Como Ler Este Relatório',
    '3. CVE-2023-54321 ' + EM + ' lodash 4.15.0',
    '4. CVE-2023-12345 ' + EM + ' express 4.16.0',
    '5. CVE-2023-99999 ' + EM + ' uuid 8.0.0',
    '6. Plano de Ação e Referências',
]

# ---------- helpers ----------
def shade_para(p, fill):
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear'); shd.set(qn('w:color'), 'auto'); shd.set(qn('w:fill'), fill)
    p._p.get_or_add_pPr().append(shd)

def shade_cell(cell, fill):
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear'); shd.set(qn('w:color'), 'auto'); shd.set(qn('w:fill'), fill)
    cell._tc.get_or_add_tcPr().append(shd)

def border(p, color=ROXO, size=20, sides=('left',)):
    pBdr = OxmlElement('w:pBdr')
    for s in sides:
        b = OxmlElement('w:' + s)
        b.set(qn('w:val'), 'single'); b.set(qn('w:sz'), str(size))
        b.set(qn('w:space'), '7'); b.set(qn('w:color'), color)
        pBdr.append(b)
    p._p.get_or_add_pPr().append(pBdr)

def sp(p, b=2, a=3, ls=1.10):
    pf = p.paragraph_format
    pf.space_before = Pt(b); pf.space_after = Pt(a); pf.line_spacing = ls

def H(doc, text, level=1, color=ROXO_ESC):
    p = doc.add_heading(text, level)
    for r in p.runs:
        r.font.color.rgb = C(color); r.font.name = 'Calibri'
        r.font.size = Pt(15 if level == 1 else 11.5)
    sp(p, 8 if level == 1 else 9, 4)
    return p

def P(doc, text='', bold=False, italic=False, size=10, color=None, align=None):
    p = doc.add_paragraph()
    if text:
        r = p.add_run(text); r.bold = bold; r.italic = italic; r.font.size = Pt(size)
        if color: r.font.color.rgb = C(color)
    if align is not None: p.alignment = align
    sp(p)
    return p

def CODE(doc, text, cap=None, size=8):
    if cap:
        c = doc.add_paragraph()
        r = c.add_run(cap); r.bold = True; r.font.size = Pt(8); r.font.color.rgb = C(CINZA)
        sp(c, 4, 1)
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.left_indent = Cm(0.3); pf.space_before = Pt(2); pf.space_after = Pt(5); pf.line_spacing = 1.0
    for i, ln in enumerate(text.strip('\n').split('\n')):
        if i: p.add_run().add_break()
        r = p.add_run(ln); r.font.name = 'Consolas'; r.font.size = Pt(size)
        r.font.color.rgb = C('1A1A2E')
        r._element.rPr.rFonts.set(qn('w:eastAsia'), 'Consolas')
    border(p, ROXO, 16); shade_para(p, CODE_BG)
    return p

def TBL(doc, headers, rows, widths=None, fill=ROXO, size=8.5, after=4):
    t = doc.add_table(rows=1, cols=len(headers)); t.style = 'Table Grid'
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]; c.text = ''
        p = c.paragraphs[0]; r = p.add_run(h)
        r.bold = True; r.font.size = Pt(size); r.font.color.rgb = C('FFFFFF')
        sp(p, 2, 2); shade_cell(c, fill)
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            c = cells[i]; c.text = ''
            p = c.paragraphs[0]
            txt, col, bd = (v[0], v[1], True) if isinstance(v, tuple) else (v, None, False)
            r = p.add_run(str(txt)); r.font.size = Pt(size); r.bold = bd
            if col: r.font.color.rgb = C(col)
            sp(p, 2, 2)
    if widths:
        for rw in t.rows:
            for i, w in enumerate(widths): rw.cells[i].width = Cm(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(after)
    return t

def BUL(doc, items, size=10, color_lead=None):
    for it in items:
        p = doc.add_paragraph(style='List Bullet')
        if isinstance(it, tuple):
            r = p.add_run(it[0]); r.bold = True; r.font.size = Pt(size)
            if color_lead: r.font.color.rgb = C(color_lead)
            r2 = p.add_run(it[1]); r2.font.size = Pt(size)
        else:
            p.add_run(it).font.size = Pt(size)
        sp(p, 1, 1, 1.08)

def CALL(doc, titulo, corpo, accent=AZUL, fill='EAF2FB', size=9.5):
    p = doc.add_paragraph()
    r = p.add_run(titulo); r.bold = True; r.font.size = Pt(size); r.font.color.rgb = C(accent)
    p.add_run().add_break()
    p.add_run(corpo).font.size = Pt(size)
    pf = p.paragraph_format
    pf.left_indent = Cm(0.25); pf.space_before = Pt(5); pf.space_after = Pt(5); pf.line_spacing = 1.12
    border(p, accent, 20); shade_para(p, fill)
    return p

def field(p, code, ph=''):
    run = p.add_run()
    f1 = OxmlElement('w:fldChar'); f1.set(qn('w:fldCharType'), 'begin')
    it = OxmlElement('w:instrText'); it.set(qn('xml:space'), 'preserve'); it.text = code
    f2 = OxmlElement('w:fldChar'); f2.set(qn('w:fldCharType'), 'separate')
    t = OxmlElement('w:t'); t.text = ph
    f3 = OxmlElement('w:fldChar'); f3.set(qn('w:fldCharType'), 'end')
    for e in (f1, it, f2, t, f3): run._r.append(e)
    return run

def PB(doc): doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

def CVE_BAR(doc, cve, pkg, sev, cor):
    p = doc.add_paragraph()
    r = p.add_run('  ' + cve + '   ·   ' + pkg)
    r.bold = True; r.font.size = Pt(14); r.font.color.rgb = C('FFFFFF')
    r2 = p.add_run('        ' + sev + '  ')
    r2.bold = True; r2.font.size = Pt(11); r2.font.color.rgb = C('FFFFFF')
    pf = p.paragraph_format; pf.space_before = Pt(0); pf.space_after = Pt(6)
    shade_para(p, cor)
    return p

# ============================================================
doc = Document()
st = doc.styles['Normal']; st.font.name = 'Calibri'; st.font.size = Pt(10)
st.element.rPr.rFonts.set(qn('w:eastAsia'), 'Calibri')
sec = doc.sections[0]
sec.top_margin = Cm(1.8); sec.bottom_margin = Cm(1.6)
sec.left_margin = Cm(2.0); sec.right_margin = Cm(2.0)
sec.different_first_page_header_footer = True
fp = sec.footer.paragraphs[0]; fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = fp.add_run('Hawkeye V2.1  ·  sample-app  ·  Confidencial ' + EM + ' uso interno        Página ')
r.font.size = Pt(7.5); r.font.color.rgb = C(CINZA)
for code in ('PAGE', 'NUMPAGES'):
    if code == 'NUMPAGES':
        x = fp.add_run(' de '); x.font.size = Pt(7.5); x.font.color.rgb = C(CINZA)
    f = field(fp, code, '1'); f.font.size = Pt(7.5); f.font.color.rgb = C(CINZA)

# ---------------- CAPA ----------------
for _ in range(4): doc.add_paragraph()
p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('H A W K E Y E'); r.bold = True; r.font.size = Pt(38); r.font.color.rgb = C(ROXO)
sp(p, 0, 2)
p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('Um tiro, um alvo. Sem desperdício.')
r.italic = True; r.font.size = Pt(10.5); r.font.color.rgb = C(CINZA)
sp(p, 0, 30)

p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
shade_para(p, ROXO)
r = p.add_run('RELATÓRIO DE VULNERABILIDADES ALCANÇÁVEIS')
r.bold = True; r.font.size = Pt(17); r.font.color.rgb = C('FFFFFF')
p.paragraph_format.space_before = Pt(12); p.paragraph_format.space_after = Pt(12)

p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('sample-app'); r.bold = True; r.font.size = Pt(15); r.font.color.rgb = C(ROXO_ESC)
sp(p, 14, 2)
p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run('Análise determinística de alcançabilidade  ·  Enriquecimento CISA KEV + FIRST EPSS')
r.font.size = Pt(10); r.font.color.rgb = C(CINZA)
sp(p, 0, 30)

TBL(doc, ['CVEs avaliadas', 'Alcançáveis', 'Ruído filtrado', 'Escore de risco'],
    [[('3', ROXO_ESC), ('2', VERMELHO), ('1', VERDE), ('65 / 100', LARANJA)]],
    widths=[4.25, 4.25, 4.25, 4.25], size=13, after=20)

TBL(doc, ['Campo', 'Valor'],
    [['Ferramenta', 'Hawkeye V2.1 ' + EM + ' Vulnerability Reachability Analyzer'],
     ['Data de emissão', '28 de setembro de 2026'],
     ['Classificação', ('CONFIDENCIAL ' + EM + ' USO INTERNO', VERMELHO)]],
    widths=[4.5, 12.5], size=9.5)

PB(doc)

# ---------------- ÍNDICE ----------------
H(doc, 'Índice', 1)
for titulo in SUMARIO:
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.space_before = Pt(6); pf.space_after = Pt(2); pf.line_spacing = 1.0
    pf.tab_stops.add_tab_stop(Cm(17.0), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
    r = p.add_run(titulo); r.bold = True; r.font.size = Pt(11); r.font.color.rgb = C(ROXO_ESC)
    r2 = p.add_run(chr(9) + str(PAGEMAP.get(titulo, '')))
    r2.bold = True; r2.font.size = Pt(11); r2.font.color.rgb = C(ROXO_ESC)

doc.add_paragraph()
CALL(doc, 'Como este relatório está organizado',
     'Cada CVE ocupa exatamente uma página, com identificação, cadeia de exploração, justificativa '
     'de alcançabilidade, contexto de risco e correção. As páginas 1 e 2 dão o panorama; a última '
     'consolida o plano de ação.', ROXO_ESC, 'EEF0FB')

PB(doc)

# ---------------- 1. SUMÁRIO EXECUTIVO ----------------
H(doc, '1. Sumário Executivo', 1)
P(doc, 'Foram avaliadas 3 vulnerabilidades presentes nas dependências do sample-app. Duas são '
       'alcançáveis a partir dos pontos de entrada da aplicação e exigem ação; uma foi descartada '
       'com justificativa técnica — o pacote é importado, mas a função vulnerável nunca executa.')

TBL(doc, ['CVE', 'Pacote', 'Alcançável', 'Risco efetivo', 'Correção', 'Prio.'],
    [['CVE-2023-54321', 'lodash 4.15.0', ('Sim ' + EM + ' nível 3', VERMELHO),
      ('Bypass de autorização', VERMELHO), '2' + EM + '4 h', ('1', VERMELHO)],
     ['CVE-2023-12345', 'express 4.16.0', ('Sim ' + EM + ' nível 2', LARANJA),
      ('Falha no parsing', LARANJA), '5 min', ('2', LARANJA)],
     ['CVE-2023-99999', 'uuid 8.0.0', ('Não', VERDE), ('Nenhum', VERDE), 'monitorar', ('—', VERDE)]],
    widths=[3.1, 3.0, 2.7, 3.6, 2.2, 1.4], size=9)

CALL(doc, 'Ação imediata ' + EM + ' CVE-2023-54321 (lodash)',
     'Dados de um endpoint público chegam sem sanitização a uma função vulnerável a Prototype Pollution. '
     'Uma única requisição contamina o Object.prototype do processo e faz verificações de permissão '
     'retornarem verdadeiro para qualquer usuário, até o reinício. Contenção em minutos com validação de '
     'schema; correção definitiva com lodash 5.0.0 na sprint corrente.', VERMELHO, 'FDECEA')

H(doc, '2. Como Ler Este Relatório', 1)
P(doc, 'A detecção é determinística: o motor constrói o grafo de chamadas a partir da AST e verifica se '
       'existe caminho real entre os pontos de entrada e a função vulnerável. Nenhuma IA participa dessa etapa.')

TBL(doc, ['Nível', 'Significado', 'Consequência prática'],
    [['1', 'Import detectado, sem caminho confirmado', 'Normalmente ruído — não priorizar'],
     ['2', 'Existe caminho de chamadas até a função vulnerável', 'Corrigir conforme severidade'],
     ['3', ('Caminho + dado do usuário fluindo por ele (taint)', VERMELHO),
      ('Máxima prioridade ' + EM + ' explorável de fora', VERMELHO)]],
    widths=[1.5, 8.0, 7.5], size=9)

P(doc, 'O enriquecimento adiciona contexto de mundo real a partir de duas fontes públicas gratuitas: '
       'CISA KEV (exploração ativa confirmada) e FIRST EPSS (probabilidade de exploração nos próximos 30 dias, '
       'com percentil). A prioridade combina os três sinais:')
CODE(doc, 'prioridade = (EPSS x 0,40) + (CISA_KEV x 0,30) + (confiança_de_alcançabilidade x 0,30)')
P(doc, 'O escore ordena a fila; ele não substitui julgamento. O EPSS mede probabilidade no ecossistema, '
       'não o impacto na sua aplicação — por isso um achado taint-reachable com impacto em autorização pode '
       'ser prioridade 1 mesmo com escore numérico moderado.', size=9.5, italic=True, color=CINZA)

PB(doc)

# ---------------- 3. CVE-2023-54321 ----------------
CVE_BAR(doc, 'CVE-2023-54321', 'lodash 4.15.0', 'SEVERIDADE ALTA', LARANJA)
P(doc, 'Prototype Pollution (CWE-1321) — versões < 5.0.0 não bloqueiam as chaves __proto__, constructor e '
       'prototype ao copiar objetos, permitindo escrita direta no protótipo global do processo.', size=9.5)

TBL(doc, ['Alcançabilidade', 'Confiança', 'EPSS', 'CISA KEV', 'Prioridade'],
    [[('Nível 3 ' + EM + ' taint', VERMELHO), '87%', '7,8 / 100  (p92)', 'Não listada', ('1', VERMELHO)]],
    widths=[3.6, 2.2, 4.2, 3.4, 3.6], size=9.5)

H(doc, 'Cadeia de exploração', 2)
CODE(doc,
"""POST /api/process-data          [entrada publica, sem schema]
  src/index.js:main > setupRoutes()
    src/handlers/data.js:processUserData(req.body)
      handleUserData(data)
        _.map(data.items, ...)    [funcao vulneravel do lodash]""", size=8)
BUL(doc, [
    ('1. Entrada ' + EM + ' ', 'endpoint público aceita JSON arbitrário, sem schema nem allowlist.'),
    ('2. Propagação ' + EM + ' ', 'req.body é repassado intacto à camada de domínio; o taint atravessa sem barreira.'),
    ('3. Entrega ' + EM + ' ', 'data.items chega a _.map(), ainda sob controle total do atacante.'),
    ('4. Escrita ' + EM + ' ', 'a chave "__proto__" resolve para Object.prototype em vez de criar propriedade própria.'),
    ('5. Impacto ' + EM + ' ', 'toda checagem de propriedade ausente passa a retornar o valor injetado.'),
], size=9.5, color_lead=LARANJA)

H(doc, 'Evidência', 2)
CODE(doc,
"""// sink alcancavel  -  src/handlers/data.js
export function handleUserData(data) {
  return _.map(data.items, (item) => ({ id: item.id, ...item }));
}                                                    ^-- spread sem filtro

# prova de exploracao (ambiente controlado)
curl -X POST /api/process-data \\
     -d '{"items":[{"id":1,"__proto__":{"isAdmin":true}}]}'
# a partir daqui, em todo o processo:   ({}).isAdmin === true""", size=7.5)

H(doc, 'Por que é explorável neste código', 2)
BUL(doc, [
    'Endpoint público, sem autenticação e sem validação de schema no caminho.',
    'lodash 4.15.0 dentro da faixa afetada, com _.map() efetivamente invocada — não é import ocioso.',
    'Taint contínuo da entrada HTTP até o sink, confirmado com 87% de confiança.',
    'Impacto global: middlewares que testam user.isAdmin passam a aprovar qualquer requisição.',
], size=9.5)

H(doc, 'Correção', 2)
CODE(doc, 'npm install lodash@^5.0.0 --save     # corrige a causa raiz\n'
          '# contencao imediata: validar entrada com zod .strict() no endpoint', size=8)
P(doc, 'Esforço 2–4 h  ·  Quebra de compatibilidade: sim (5.x removeu variantes legadas)  ·  '
       'Ajustes: substituir _.assign() por Object.assign() e revisar src/handlers/data.js.', size=9.5)

PB(doc)

# ---------------- 4. CVE-2023-12345 ----------------
CVE_BAR(doc, 'CVE-2023-12345', 'express 4.16.0', 'SEVERIDADE ALTA', LARANJA)
P(doc, 'Falha no tratamento de requisições em versões < 4.17.1. O trecho afetado é alcançado pelo middleware '
       'de parsing do corpo, registrado no bootstrap e presente no pipeline de toda requisição.', size=9.5)

TBL(doc, ['Alcançabilidade', 'Confiança', 'EPSS', 'CISA KEV', 'Prioridade'],
    [[('Nível 2 ' + EM + ' função', LARANJA), '92%', 'sem dado publicado', 'Não listada', ('2', LARANJA)]],
    widths=[3.6, 2.2, 4.2, 3.4, 3.6], size=9.5)

H(doc, 'Cadeia de exploração', 2)
CODE(doc,
"""src/index.js:main > setupRoutes()
  app.use(bodyParser)             [registro no bootstrap]
    express internals             [trecho vulneravel]""", size=8)
BUL(doc, [
    ('1. Bootstrap ' + EM + ' ', 'setupRoutes() registra o middleware de parsing via app.use(bodyParser).'),
    ('2. Pipeline ' + EM + ' ', 'o middleware passa a interceptar o corpo de toda requisição recebida.'),
    ('3. Delegação ' + EM + ' ', 'o parsing delega internamente ao código do Express afetado pela falha.'),
    ('4. Gatilho ' + EM + ' ', 'uma requisição com corpo malformado alcança o trecho vulnerável.'),
], size=9.5, color_lead=LARANJA)

H(doc, 'Por que é explorável neste código', 2)
BUL(doc, [
    'O middleware está no caminho de toda requisição — não há rota que escape do trecho afetado.',
    'A versão instalada (4.16.0) está dentro da faixa vulnerável (< 4.17.1).',
    'Alcançabilidade de nível 2: caminho confirmado, mas sem fluxo de taint adicional além do corpo '
    'já tratado pelo próprio middleware — risco efetivo menor que o da CVE-2023-54321.',
], size=9.5)

H(doc, 'Correção', 2)
CODE(doc, 'npm install express@4.17.1 --save', size=8)
P(doc, 'Esforço 5 min  ·  Quebra de compatibilidade: não (patch na mesma versão maior)  ·  '
       'Ajustes: nenhum além de validar a suíte de testes.', size=9.5)
CALL(doc, 'Aplicar já',
     'Sem quebra de compatibilidade e com esforço de minutos, esta correção não precisa aguardar a janela '
     'de manutenção planejada para o lodash.', VERDE, 'E8F5E9')

PB(doc)

# ---------------- 5. CVE-2023-99999 ----------------
CVE_BAR(doc, 'CVE-2023-99999', 'uuid 8.0.0', 'NÃO ALCANÇÁVEL', VERDE)
P(doc, 'Falha no mecanismo de seeding customizado de números aleatórios em versões < 8.3.2. '
       'Um scanner convencional reportaria este achado como vulnerável; a análise de alcançabilidade '
       'demonstra que o código afetado nunca é executado.', size=9.5)

TBL(doc, ['Alcançabilidade', 'Confiança', 'EPSS', 'CISA KEV', 'Prioridade'],
    [[('Nível 1 ' + EM + ' só import', VERDE), '100%', 'não consultado', 'Não listada', ('Monitorar', VERDE)]],
    widths=[3.6, 2.2, 4.2, 3.4, 3.6], size=9.5)

H(doc, 'Por que NÃO é explorável neste código', 2)
CODE(doc,
"""// uso encontrado na aplicacao  ->  caminho seguro
import { v4 as uuidv4 } from 'uuid';
const id = uuidv4();                              // delega a crypto.randomUUID()

// uso que tornaria a CVE alcancavel  ->  AUSENTE no projeto
const id = uuidv4({ rng: customSeedFunction });   // nenhuma ocorrencia""", size=8)

TBL(doc, ['Critério', 'Resultado', 'Evidência'],
    [['Pacote instalado e importado', ('Sim', LARANJA), 'uuid 8.0.0 presente e importado'],
     ['Função vulnerável chamada', ('Não', VERDE), 'Nenhuma chamada com rng customizado no código'],
     ['Caminho de execução até o sink', ('Não', VERDE), 'Sem aresta no grafo até o trecho afetado'],
     ['Risco efetivo hoje', ('Nenhum', VERDE), 'Falso positivo operacional, filtrado com justificativa']],
    widths=[5.0, 2.4, 9.6], size=9)

H(doc, 'Ação recomendada', 2)
P(doc, 'Nenhuma correção necessária. Incorporar a atualização oportunisticamente em manutenção de rotina '
       'e reavaliar a classificação caso a aplicação passe a usar seeding customizado de UUID.', size=9.5)

CALL(doc, 'O valor da análise de alcançabilidade',
     'Este achado representa 33% do que um scanner convencional reportaria. Filtrá-lo com justificativa '
     'técnica evita abrir chamado, negociar janela de manutenção e pagar esforço de regressão — sem reduzir '
     'a postura de segurança, já que a decisão fica auditável e é reavaliada a cada execução.', AZUL, 'EAF2FB')

PB(doc)

# ---------------- 6. PLANO DE AÇÃO ----------------
H(doc, '6. Plano de Ação e Referências', 1)

TBL(doc, ['Prio.', 'CVE', 'Ação', 'Esforço', 'Quebra', 'Quando'],
    [[('1', VERMELHO), 'CVE-2023-54321', 'Validar schema (contenção) + lodash 5.0.0', '2' + EM + '4 h', 'Sim', 'Sprint atual'],
     [('2', LARANJA), 'CVE-2023-12345', 'Atualizar express para 4.17.1', '5 min', 'Não', 'Imediato'],
     [('—', VERDE), 'CVE-2023-99999', 'Monitorar ' + EM + ' não alcançável', '—', '—', 'Rotina']],
    widths=[1.3, 3.2, 6.6, 1.9, 1.5, 2.5], size=9)

H(doc, 'Sequenciamento sugerido', 2)
BUL(doc, [
    ('Dia 0 ' + EM + ' ', 'atualizar o express (5 min) e implantar validação de schema no /api/process-data.'),
    ('Dias 1 a 3 ' + EM + ' ', 'migrar o lodash para 5.0.0 em branch dedicada, com testes cobrindo os vetores '
     'de prototype pollution descritos na página 4.'),
    ('Dia 4 ' + EM + ' ', 'reexecutar o Hawkeye e comparar com esta linha de base.'),
    ('Contínuo ' + EM + ' ', 'integrar ao CI/CD com bloqueio de merge para achados de prioridade 1.'),
], size=9.5)

CODE(doc, 'vra analyze . --level 3 --output analysis-pos-correcao.json\n'
          'vra report analysis-pos-correcao.json --enrichment --format html', size=8)
P(doc, 'Resultado esperado após as correções: alcançáveis de 2 para 0 e escore de risco de 65 para '
       'aproximadamente 10.', size=9.5)

H(doc, 'Fontes e referências', 2)
TBL(doc, ['Fonte', 'O que fornece', 'Endereço'],
    [['CISA KEV', 'Vulnerabilidades sob exploração ativa confirmada e uso em ransomware',
      'cisa.gov/known-exploited-vulnerabilities'],
     ['FIRST EPSS', 'Probabilidade de exploração em 30 dias, com percentil', 'api.first.org/epss'],
     ['CWE-1321', 'Classe da CVE-2023-54321 (Prototype Pollution)', 'cwe.mitre.org/data/definitions/1321'],
     ['Hawkeye', 'Motor determinístico de alcançabilidade (AST + grafo de chamadas)',
      'github.com/lucasvsantos591-hue/hawkeye']],
    widths=[2.5, 8.5, 6.0], size=9)

P(doc, 'Ambas as fontes de enriquecimento são públicas e gratuitas, consultadas sem autenticação e com '
       'cache de 1 hora. A detecção é determinística: duas execuções sobre o mesmo código produzem sempre '
       'o mesmo conjunto de achados.', size=9, italic=True, color=CINZA)

doc.add_paragraph()
p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
shade_para(p, CINZA_CL)
r = p.add_run('Hawkeye V2.1  ·  28 de setembro de 2026  ·  CONFIDENCIAL ' + EM + ' USO INTERNO')
r.italic = True; r.font.size = Pt(8.5); r.font.color.rgb = C(CINZA)
p.paragraph_format.space_before = Pt(10); p.paragraph_format.space_after = Pt(10)

s = doc.settings.element
uf = OxmlElement('w:updateFields'); uf.set(qn('w:val'), 'true'); s.append(uf)
OUT = '/home/usuario/Relatorio_Hawkeye_V2.1_sample-app.docx'
doc.save(OUT)
print('OK ->', OUT)
