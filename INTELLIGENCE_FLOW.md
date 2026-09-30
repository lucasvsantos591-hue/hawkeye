# 🧠 Fluxo de Inteligência no Hawkeye V2.1

## Pergunta: Onde Entra a IA?

**Resposta:** Em dois momentos!

## 🔄 Fluxo Completo

```
┌──────────────────────────────────────────────────────────────┐
│ 1. ANALYZE - Análise Estática (SEM IA)                       │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│ • Lê package.json → lista de dependências                    │
│ • AST parsing → analisa código-fonte                         │
│ • Taint analysis → rastreia dados do usuário                 │
│ • Reachability detection → determina se é alcançável         │
│                                                                │
│ ✓ DETERMINÍSTICO - Sempre mesmos resultados                │
│ ✓ RÁPIDO - Sem chamadas externas                            │
│ ✓ OFFLINE - Funciona sem internet                           │
│                                                                │
│ Saída: findings.json                                         │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│ 2. EXPOSE - Análise de Exposição à Internet (SEM IA)        │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│ • DNS lookup → resolve hostname                              │
│ • SSL check → certifica HTTPS                                │
│ • HTTP probe → testa endpoints públicos                      │
│ • CDN detection → identifica provedor                        │
│                                                                │
│ ✓ NETWORK-BASED - Verifica exposição real                   │
│ ✓ OBJETIVO - Usa dados públicos (DNS, WHOIS)               │
│                                                                │
│ Saída: exposure.json                                         │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│ 3a. REPORT - Enriquecimento (SEM IA)                        │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│ • CISA KEV → vulnerabilidades exploradas na prática         │
│ • FIRST EPSS → score de probabilidade de exploração         │
│ • Priority Calculation → combina fatores em score           │
│                                                                │
│ ✓ PUBLIC DATA - Usa APIs públicas (CISA, FIRST)            │
│ ✓ DETERMINISTICO - Fórmula matemática fixa                 │
│                                                                │
│ Saída: findings + enrichment                                 │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│ 3b. REPORT + IA - Geração de Remediações (COM IA) ⭐        │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│ OPTATIVO: --ai-provider [claude|openai|gemini]              │
│                                                                │
│ IA é usada para:                                             │
│ • Sugerir remediações específicas                            │
│ • Recomendar versões seguras                                │
│ • Estimar esforço de correção                               │
│ • Detectar breaking changes                                  │
│ • Sugerir ajustes de código                                  │
│                                                                │
│ Exemplo com Claude:                                          │
│ $ node ./dist/cli/index.js report findings.json \            │
│     --enrichment \                                            │
│     --ai-provider claude \                                    │
│     --ai-token sk-... \                                       │
│     --format html                                             │
│                                                                │
│ ✓ INTELIGENTE - Contexto-aware recommendations              │
│ ✓ OPCIONAL - Funciona sem IA também                         │
│ ✓ CUSTOMIZAVEL - Suporta múltiplos provedores               │
│                                                                │
│ Saída: findings + enrichment + AI remediations               │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│ 4. VISUALIZAÇÃO - Relatório HTML/DOCX                        │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│ Mostra:                                                       │
│ • Todas as vulnerabilidades detectadas                       │
│ • Análise de reachability com confiança                      │
│ • Cadeia de exploração (call chain)                          │
│ • Enriquecimento (EPSS, CISA, Priority)                      │
│ • Contexto de exposição à internet                           │
│ • [OPCIONAL] Remediações sugeridas por IA                   │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

## Comparação: Com IA vs Sem IA

### SEM IA (Padrão)

```bash
node ./dist/cli/index.js analyze /projeto --output findings.json
node ./dist/cli/index.js report findings.json --enrichment --format html
```

**Resultado:**
- ✅ Vulnerabilidades detectadas
- ✅ Reachability analysis
- ✅ Priority scores (EPSS + CISA KEV)
- ❌ Remediações genéricas (apenas da base de dados)
- ⏱️ Muito rápido (segundos)

### COM IA (Claude, OpenAI, etc)

```bash
node ./dist/cli/index.js analyze /projeto --output findings.json
node ./dist/cli/index.js report findings.json \
  --enrichment \
  --ai-provider claude \
  --ai-token sk-... \
  --ai-model claude-opus-5-5 \
  --format html
```

**Resultado:**
- ✅ Tudo do anterior, MAIS:
- ✅ Remediações inteligentes (específicas para seu projeto)
- ✅ Detecção de breaking changes
- ✅ Estimativa de esforço realista
- ✅ Sugestões de ajuste de código
- ✅ Contexto de segurança
- ⏱️ Mais lento (chamadas à IA - 1-2 min)

## Exemplo Real: CVE-2018-16487 (lodash)

### SEM IA

```json
{
  "cve_id": "CVE-2018-16487",
  "package": "lodash",
  "vulnerability": "Prototype pollution",
  "remediation": {
    "type": "MINOR",
    "required_version": "4.17.19",
    "action": "npm install lodash@4.17.19 --save",
    "effort_estimate": "Unknown"
  }
}
```

### COM IA (Claude)

```json
{
  "cve_id": "CVE-2018-16487",
  "package": "lodash",
  "vulnerability": "Prototype pollution in _.defaultsDeep()",
  "remediation": {
    "type": "MINOR",
    "required_version": "4.17.19",
    "breaking_changes": false,
    "changes_needed": [
      "npm install lodash@5.0.0 --save",
      "Validar entrada com zod .strict() no endpoint /api/process-data",
      "Substituir _.assign() por Object.assign() em src/handlers/data.js"
    ],
    "action": "npm install lodash@5.0.0 --save",
    "effort_estimate": "2–4 h",
    "notes": "Quebra de compatibilidade com 5.x. Revisar uso de _assign() em 3 arquivos."
  }
}
```

## Caso de Uso: Análise Completa com Internet-Facing

```bash
# PASSO 1: Analisar o projeto
$ node ./dist/cli/index.js analyze /seu/projeto \
  --output findings.json

# PASSO 2: Verificar se está exposto à internet
$ node ./dist/cli/index.js expose seu-dominio.com \
  --output exposure.json

# PASSO 3: Gerar relatório com IA + exposição
$ node ./dist/cli/index.js report findings.json \
  --enrichment \
  --ai-provider claude \
  --ai-token sk-... \
  --format html \
  --output security-report.html

# RESULTADO:
# - Vulnerabilidades reachable detectadas
# - Se a vulnerabilidade está em serviço public (exposição)
# - Remediações inteligentes com esforço estimado
# - Priority scores em contexto de risco real
```

## Quando Usar IA?

### ✅ USE IA SE:
- Você tem muitos CVEs para corrigir
- Precisa de estimativa realista de esforço
- Quer evitar breaking changes
- Projetos grandes/complexos
- Integração em CI/CD automático

### ❌ SEM IA ESTÁ ÓTIMO SE:
- Apenas quer detectar vulnerabilidades
- Conhece bem seu projeto
- Quer análise rápida/offline
- Sem budget para chamadas de IA
- Remediações são óbvias

## Fluxo Resumido

```
INPUT
  └─ Projeto Node.js

PHASE 1: DETECTION (sem IA)
  └─ analyze → findings.json

PHASE 2: EXPOSURE (sem IA)
  └─ expose → exposure.json

PHASE 3: ENRICHMENT (sem IA)
  └─ report + CISA KEV + EPSS → priority scores

PHASE 4: INTELLIGENCE (com IA OPCIONAL)
  └─ report --ai-provider → smart remediations

OUTPUT
  └─ HTML/DOCX com tudo integrado
```

## Resumo: IA no Hawkeye

| Momento | Função | IA? | Velocidade |
|---------|--------|-----|-----------|
| **Analyze** | Detectar vulnerabilidades | ❌ | ⚡ Instant |
| **Expose** | Verificar exposição internet | ❌ | ⚡ 5-10s |
| **Enrich** | CISA KEV + EPSS | ❌ | ⚡ Instant |
| **Remediate** | Sugerir correções | ✅ Optional | 🐢 1-2 min |
| **Report** | Gerar documento | ❌ | ⚡ Instant |

**TL;DR:** IA entra OPCIONALMENTE na geração de remediações, tornando as sugestões inteligentes e contextualmente relevantes! 🚀
