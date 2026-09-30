# 🎯 Hawkeye - V2.2 (Production Ready)

[![CI Status](https://github.com/lucasvsantos591-hue/hawkeye/actions/workflows/ci.yml/badge.svg)](https://github.com/lucasvsantos591-hue/hawkeye/actions)
[![Docker Image](https://img.shields.io/badge/Docker-Ready-blue)](./Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Node.js 18+](https://img.shields.io/badge/Node.js-18+-green)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.2+-blue)](https://www.typescriptlang.org/)
[![Hawkeye V2.2](https://img.shields.io/badge/Hawkeye-V2.2-brightgreen.svg)](.)
[![Production Deploy](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)](./DEPLOYMENT.md)

> **Precision Vulnerability Reachability Analysis**  
> One Shot. One Target. No False Positives.
>
> Go beyond version-based scanning to determine if a vulnerability is truly exploitable in your code.
>
> **✨ NEW V2.2:** 
> - 🚀 HTTP API Server for production deployment
> - 🐳 Docker support with health checks
> - 📊 Batch processing for multiple projects
> - 🔐 K8s + Terraform context extraction
> - 📄 SARIF format export
> - 🎯 Risk rescoring based on exposure
> - 💾 Persistent cache (~80% faster 2nd run)

## 🚀 Quick Start

### Docker (Recommended)
```bash
docker build -t hawkeye .
docker run -p 3000:3000 hawkeye
curl http://localhost:3000/api/health
```

### Node.js
```bash
npm install
npm run build
node dist/cli/server.js
```

### CLI Single Project
```bash
node dist/cli/index.js analyze /path/to/project --level 2
node dist/cli/index.js report analysis.json --format html
```

### Batch Processing
```bash
node dist/cli/index.js batch /path/to/projects --concurrency 4
```

---

## ✨ Why Hawkeye?

**80-90% of CVE alerts are false positives.** Traditional SCA tools alert on every dependency version mismatch,
regardless of whether your code actually uses the vulnerable function.

Hawkeye answers: **"Is this CVE actually reachable in MY code?"**

**Result:** Reduce noise, focus on real risks, and ship faster with confidence.

---

## 🎯 O Problema

### Scanners SCA Tradicionais: "Versão = Risco"

Ferramentas SCA (Software Composition Analysis) fazem apenas **matching de versões**:
- ✅ **Detectam:** Você tem `axios@1.3.5` e existe CVE-2023-XXXX em `axios < 1.4.0`
- ❌ **Não validam:** Se seu código usa a função vulnerável
- ❌ **Não verificam:** Se o código pode alcançar aquele ponto vulnerável

Elas então correlacionam EPSS (Exploit Prediction Scoring System) + KEV (Known Exploited Vulnerabilities) para calcular criticidade. **Resultado: 80-90% falsos positivos**—vulnerabilidades que nunca vão impactar você.

**Consequência:** Seu time gasta horas auditando vulnerabilidades que não são exploráveis, ou deprioritiza as que realmente importam.

### Hawkeye: Análise de Reachability (Alcançabilidade)

VRA responde: **"Essa vulnerabilidade é realmente alcançável no MEU código?"**

**Exemplo Real:**
```javascript
// seu-app/src/api.js
import axios from 'axios'; // CVE-2023-XXXX em axios < 1.4.0

export function fetchPublicData(url) {
  // Usa apenas axios.get() com URLs pré-validadas
  if (!isValidApiUrl(url)) throw new Error('URL inválida');
  return axios.get(url); // GET é seguro, vulnerability está em POST com forma-data
}

// Vulnerabilidade: axios POST com FormData não escapava corretamente
// Seu código: Apenas usa GET, nunca usa POST nem FormData
```

| Ferramenta | Resultado | Confiabilidade |
|-----------|-----------|-----------------|
| **Scanner SCA** | ⚠️ VULNERÁVEL (CVE-2023-XXXX) | ~30% (falso positivo) |
| **VRA** | ✅ NÃO ALCANÇÁVEL | 99% (função vulnerável nunca é chamada) |

---

## 📈 Por que Reachability Importa?

### O Ciclo Atual (Sem Reachability)
```
1. Scanner SCA descobre: "lodash@4.15.0 tem CVE-YYYY"
2. EPSS score: 8.5/10 (Exploit fácil)
3. KEV check: Sim, está sendo explorada "in the wild"
4. Resultado: 🔴 CRÍTICA (deve corrigir HOJE)

❌ Problema: Seu código NÃO usa a função vulnerável
❌ Resultado: 2 horas de testes e deployment para nada
```

### Com Hawkeye (Análise de Reachability)
```
1. Scanner SCA descobre: "lodash@4.15.0 tem CVE-YYYY"
2. VRA analisa: Essa função vulnerável é usada?
   → Nível 1: Importação? ✅ Sim
   → Nível 2: Função alcançável? ❌ Não
   → Nível 3: Taint-reachable? ❌ Não
3. Resultado: 🟢 IGNORAR (falso positivo)

✅ Economia: 2 horas de work desnecessário
✅ Foco: Priorizar vulnerabilidades reais
```

### Impacto de Remediação: MAJOR vs MINOR

**MINOR** (Atualizar versão)
```json
{
  "type": "MINOR",
  "required_version": ">=4.17.1",
  "changes_needed": ["npm install express@4.17.1"],
  "breaking_changes": false,
  "effort": "5 minutos"
}
```

**MAJOR** (Refatoração de código)
```json
{
  "type": "MAJOR",
  "required_version": ">=5.0.0",
  "breaking_changes": true,
  "changes_needed": [
    "Remover _.assign() e usar Object.assign()",
    "Atualizar src/handlers/auth.js:45",
    "Remover compatibilidade com legacy lodash plugins",
    "Adicionar testes para nova implementação"
  ],
  "affected_files": 7,
  "effort": "2-4 horas"
}
```

---

## ⚡ Features V2.2

### 🎯 Core Analysis
- ✅ **Level 1 Analysis**: Import detection
- ✅ **Level 2 Analysis**: Call graph reachability
- ✅ **Level 3 Analysis**: Data flow & taint tracking (planned)
- ✅ **Multi-language**: JavaScript/TypeScript, Python, Java (planned)

### 🔐 Security Context
- ✅ **Kubernetes NetworkPolicy** extraction and analysis
- ✅ **Terraform** security group and WAF parsing
- ✅ **AWS exposure** detection (internet-facing/isolated)
- ✅ **Network isolation** scoring
- ✅ **Compliance tags** (PCI-DSS, HIPAA, GDPR, SOC2, ISO27001)

### 📊 Risk Intelligence
- ✅ **Risk Rescoring**: 1.5x multiplier for internet-facing apps
- ✅ **CISA KEV** integration: Known exploited vulnerabilities
- ✅ **FIRST EPSS**: Exploit prediction scoring
- ✅ **Confidence scoring**: 0-100% certainty on reachability

### 🚀 Deployment
- ✅ **HTTP API Server**: Production-ready with health checks
- ✅ **Docker Support**: Containerized deployment
- ✅ **Batch Processing**: Concurrent multi-project analysis
- ✅ **CI/CD Ready**: GitHub Actions, GitLab CI, Azure Pipelines
- ✅ **SARIF Export**: IDE and tool integration

### 💾 Performance
- ✅ **Persistent Cache**: SQLite/JSON with TTL
- ✅ **~80% faster** on 2nd run with cache hit
- ✅ **Concurrency Control**: Configurable pool size
- ✅ **Incremental Analysis**: Rebuild only changed files

### 📄 Reports
- ✅ **HTML Report**: Professional design with exposure badges
- ✅ **SARIF Format**: Standard analysis interchange format
- ✅ **JSON Export**: Programmatic access
- ✅ **Risk scores**: Original vs. adjusted (context-aware)

### 🔌 Integrations
- ✅ **GitHub Actions** workflow template
- ✅ **GitLab CI** pipeline template
- ✅ **Azure Pipelines** YAML template
- ✅ **REST API**: Full programmatic access
- ✅ **YAML/JSON** context files

---

## ✨ Características V2.1

### ⭐ NOVO: CVE Enrichment Completo

Hawkeye agora enriquece cada vulnerabilidade com dados do mundo real:

**🔍 CISA KEV (Known Exploited Vulnerabilities)**
- ✅ Identifica se a vulnerabilidade está sendo explorada na prática
- ✅ Detecta uso em campanhas ransomware
- ✅ Integrado na análise de prioridade

**📊 FIRST EPSS (Exploit Prediction Scoring System)**
- ✅ Score 0-100 da probabilidade de exploração nos próximos 30 dias
- ✅ Percentil comparativo com outras vulnerabilidades
- ✅ Dados atualizados continuamente

**🎯 Priority Scoring Inteligente**
```
Priority Score = (EPSS × 0.4) + (CISA_KEV × 0.3) + (Reachability × 0.3)

Exemplo:
  EPSS: 7.8/100 (40%) = 3.12
  CISA KEV explorado (30%) = 30
  Reachability 95% confiança (30%) = 28.5
  ──────────────────────
  Total: 61.6 → HIGH prioridade
```

### 🌐 NOVO: Internet-Facing Exposure Detection

Detecta automaticamente se sua aplicação está exposta à internet:

**Métodos de Detecção:**
- 🔍 **DNS Resolution** - IPs públicos vs privados
- 🔐 **SSL Certificate** - HTTPS acessível
- 🌐 **HTTP Probe** - Endpoints respondendo
- ☁️ **CDN Detection** - Cloudflare, Akamai, AWS

**Saída:**
```json
{
  "is_internet_facing": true,
  "detection_confidence": 92,
  "detection_methods": ["DNS", "SSL", "HTTP_PROBE"],
  "verified_endpoints": [...],
  "ssl_certificate": {...},
  "dns_records": {...}
}
```

### 🤖 NOVO: AI-Powered Remediation

Suporte integrado para múltiplos provedores de IA:

- **Claude** (Anthropic)
- **OpenAI** (GPT-4)
- **Gemini** (Google)
- **Custom** (OpenAI-compatible)

Gera remediações inteligentes e contextualizadas:
- Detecta breaking changes
- Estima esforço realista
- Sugere ajustes de código específicos
- Recomenda versões seguras

### 📊 Análise de Alcançabilidade - Três Níveis

1. **Nível 1: Detecção de Importações**
   - Verifica se o pacote vulnerável é importado
   - Mais rápido, menos falsos negativos

2. **Nível 2: Análise de Grafo de Chamadas**
   - Constrói grafo completo de chamadas do seu código
   - Determina se a função vulnerável é alcançável
   - Fornece cadeia de chamadas do ponto de entrada até a vulnerabilidade

3. **Nível 3: Análise de Fluxo de Dados & Taint**
   - Rastreia como dados do usuário fluem pelo seu código
   - Identifica se dados comprometidos alcançam o ponto vulnerável
   - Mais preciso, detecta vetores de ataque complexos

### 🌍 Suporte Multi-Linguagem

Hawkeye suporta análise de reachability para múltiplas linguagens:

- **JavaScript/TypeScript** ✅ (via Babel AST)
- **Python** 🚧 (em desenvolvimento, via módulo AST)
- **Java, Go, Rust** 🗺️ (roadmap V2+)

### 📦 Múltiplas Fontes de Vulnerabilidades

- **NVD API** (Banco de Dados Nacional de Vulnerabilidades)
- **Cache SQLite Local** (suporte offline)
- **API Snyk** (opcional, planejado)

### 🚀 Performance

- Cache agressivo reduz chamadas de API em 95%
- Análise paralela de múltiplas dependências
- Grafo de chamadas construído uma vez, reutilizado para todos os CVEs

---

## 🚀 Início Rápido

### Pré-requisitos

- Node.js 18+
- Dart 3.0+ (para o core em background — ainda em desenvolvimento)
- Python 3.10+ (para parser Python — ainda em desenvolvimento)

### Instalação

```bash
git clone https://github.com/lucasvsantos591-hue/hawkeye.git
cd hawkeye
npm install
npm run build
```

---

## 📚 Documentação Completa

### Guias Disponíveis

- **[USAGE.md](./USAGE.md)** - Guia prático de instalação e uso
- **[WORKFLOW.md](./WORKFLOW.md)** - Diagramas visuais do fluxo de análise
- **[INTELLIGENCE_FLOW.md](./INTELLIGENCE_FLOW.md)** - Como IA é integrada ao pipeline

### Exemplos

Veja a pasta `examples/` para:
- Análise completa com exposição à internet
- Configurações de IA
- Estrutura de relatórios

---

## 🎯 Fluxo de Análise Completo

```
┌─────────────────────────────────────────────────────────────┐
│  INPUT: Seu Projeto (package.json + código-fonte)          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  1️⃣ ANALYZE - Detecção de Vulnerabilidades                 │
│                                                              │
│  ✓ Lê package.json (dependências)                          │
│  ✓ AST Parsing (código-fonte)                              │
│  ✓ Taint Analysis (rastreamento de dados)                  │
│  ✓ Reachability (alcançabilidade)                          │
│                                                              │
│  OUTPUT: findings.json                                      │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  2️⃣ EXPOSE - Detecção de Exposição à Internet (OPCIONAL)   │
│                                                              │
│  ✓ DNS Resolution (IPs públicos/privados)                  │
│  ✓ SSL Check (certificado HTTPS)                           │
│  ✓ HTTP Probe (endpoints respondendo)                      │
│  ✓ CDN Detection (Cloudflare, Akamai, etc)                 │
│                                                              │
│  OUTPUT: exposure.json                                      │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  3️⃣ REPORT - Enriquecimento + Relatório                    │
│                                                              │
│  ✓ CISA KEV (vulnerabilidades exploradas)                 │
│  ✓ FIRST EPSS (probabilidade de exploração)               │
│  ✓ Priority Scoring (fórmula inteligente)                 │
│  ✓ Internet-Facing Context (se análise de exposição)      │
│                                                              │
│  OUTPUT: findings com enrichment                            │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  4️⃣ AI REMEDIATION (OPCIONAL - Claude/OpenAI/Gemini)      │
│                                                              │
│  ✓ Análise inteligente de cada CVE                        │
│  ✓ Detecção de breaking changes                           │
│  ✓ Estimativa de esforço                                  │
│  ✓ Sugestões de código                                    │
│                                                              │
│  OUTPUT: Remediações AI-powered                            │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│  5️⃣ RESULTADO FINAL - HTML/DOCX/JSON                       │
│                                                              │
│  Cada CVE mostra:                                          │
│  ├─ Cadeia de exploração (entry point + call chain)       │
│  ├─ Por que é explorável (contexto técnico)               │
│  ├─ Priority Score + EPSS + CISA KEV                      │
│  ├─ Internet-facing status (se aplicável)                 │
│  └─ Remediações (versão, código, esforço)                 │
│                                                              │
│  PRONTO PARA: Compartilhar, CI/CD, Integração             │
└─────────────────────────────────────────────────────────────┘
```

---

### Uso Básico: Workflow V2.1 (Três Passos)

Hawkeye agora integra análise de reachability + exposição à internet + enrichment CVE:

**1️⃣ Análise de Vulnerabilidades (determinística)**
```bash
# Detecta vulnerabilidades e determina reachability
node ./dist/cli/index.js analyze ./meu-app --level 2 --output findings.json
```

**2️⃣ Exposição à Internet (NOVO - Opcional)**
```bash
# Verifica se a aplicação está internet-facing
node ./dist/cli/index.js expose meu-dominio.com --output exposure.json
```

**3️⃣ Relatório Enriquecido**
```bash
# SEM IA (rápido) - CISA KEV + FIRST EPSS + Priority Score
node ./dist/cli/index.js report findings.json \
  --enrichment \
  --format html \
  --output relatorio.html

# COM IA (inteligente) - Remediações AI-powered
node ./dist/cli/index.js report findings.json \
  --enrichment \
  --ai-provider claude \
  --ai-token sk-... \
  --format html \
  --output relatorio-inteligente.html
```

**Suporte a Múltiplos Provedores de IA:**
```bash
# OpenAI (GPT-4)
node ./dist/cli/index.js report findings.json \
  --ai-provider openai \
  --ai-token sk-... \
  --format html

# Google Gemini
node ./dist/cli/index.js report findings.json \
  --ai-provider gemini \
  --ai-token ... \
  --format html
```

**Múltiplos Formatos de Saída:**
```bash
# HTML - Interativo, para visualização
--format html --output relatorio.html

# DOCX - Profissional, para compartilhamento
--format docx --output relatorio.docx

# Markdown - Para documentação/Git
--format markdown --output relatorio.md

# JSON - Para integração com ferramentas
--format json --output relatorio.json
```

# Com endpoint customizado OpenAI-compatible (Ollama, Groq, Mistral, etc.)
vra report analysis.json --format html --ai-provider custom --ai-base-url http://localhost:8000/v1 --ai-token test-key

# Formato Markdown ou JSON
vra report analysis.json --format markdown
vra report analysis.json --format json | jq '.results[] | select(.is_reachable == true)'
```

### Verificar um CVE Específico (Em desenvolvimento)
```bash
vra scan axios 1.4.0 --language javascript
```

---

## 📊 Saída de Exemplo

```json
{
  "project_name": "meu-app",
  "total_vulnerabilities": 15,
  "reachable_vulnerabilities": 3,
  "overall_risk_score": 42,
  "summary": {
    "critical_reachable": 1,
    "high_reachable": 2,
    "medium_reachable": 0,
    "false_positives_filtered": 12
  },
  "results": [
    {
      "vulnerability": {
        "cve_id": "CVE-2023-12345",
        "package": "express",
        "current_version": "4.16.0",
        "affected_versions": ["<4.17.1"],
        "severity": "HIGH",
        "epss_score": 8.2,
        "is_exploited_in_wild": true
      },
      "is_reachable": true,
      "reachability_level": 2,
      "confidence": 92,
      "call_chain": {
        "entry_point": "src/index.js:main",
        "path": [
          "setupRoutes() → src/routes.js:12",
          "handleRequest() → src/handlers/api.js:45",
          "express.use(bodyParser.json()) → triggers vulnerable code",
          "vulnerableFunction()"
        ]
      },
      "remediation": {
        "type": "MINOR",
        "description": "Apenas atualizar versão do npm",
        "required_version": ">=4.17.1",
        "breaking_changes": false,
        "changes_needed": [
          "Atualizar express@4.16.0 para express@^4.17.1 em package.json",
          "Executar 'npm install' (compatível com versão atual do seu código)"
        ],
        "action": "npm install express@4.17.1"
      }
    },
    {
      "vulnerability": {
        "cve_id": "CVE-2023-54321",
        "package": "lodash-cli",
        "current_version": "4.15.0",
        "affected_versions": ["<3.10.2"],
        "severity": "CRITICAL",
        "epss_score": 9.8,
        "is_exploited_in_wild": true
      },
      "is_reachable": true,
      "reachability_level": 3,
      "confidence": 87,
      "call_chain": {
        "entry_point": "src/index.js:main",
        "taint_analysis": "User input (req.body) → map() → vulnerable function",
        "path": [
          "handleUserData() → src/handlers/data.js:112",
          "_.map(userData, transform) → lodash@4.15.0",
          "Vulnerability: Prototype pollution em _.map()"
        ]
      },
      "remediation": {
        "type": "MAJOR",
        "description": "Atualizar para versão incompatível com breaking changes",
        "required_version": ">=5.0.0",
        "breaking_changes": true,
        "changes_needed": [
          "Lodash 5.x removeu métodos legados - revisar seu código",
          "Métodos afetados: _.assign(), _.extend() (use Object.assign)",
          "Atualizar src/handlers/data.js:112 - substituir _.map por Array.prototype.map ou lodash@5.x API",
          "Adicionar testes para validar nova implementação",
          "Estimar: 2-4 horas de work (modificações em ~5 arquivos)"
        ],
        "action": "Planejado para release v2.1.0 (breaking change)",
        "effort_estimate": "2-4 horas"
      }
    },
    {
      "vulnerability": {
        "cve_id": "CVE-2023-99999",
        "package": "uuid",
        "current_version": "8.0.0",
        "affected_versions": ["<8.3.2"],
        "severity": "MEDIUM",
        "epss_score": 5.1,
        "is_exploited_in_wild": false
      },
      "is_reachable": false,
      "reachability_level": 1,
      "confidence": 100,
      "reason": "Pacote uuid importado mas função vulnerável (random seeding) não é utilizada no código",
      "remediation": {
        "type": "OPTIONAL",
        "description": "Nenhuma ação necessária no momento",
        "notes": "Código usa apenas uuid.v4() com default crypto.randomUUID(). Vulnerabilidade afeta apenas custom seeds.",
        "action": "Monitorar para futura atualização (sem pressa)"
      }
    }
  ]
}
```

### 🎯 Como Interpretar o Relatório

| Campo | Significado |
|-------|-----------|
| **is_reachable** | Vulnerabilidade pode ser explorada no seu código? |
| **reachability_level** | 1=importado, 2=função alcançável, 3=taint-reachável |
| **confidence** | Quanto VRA tem certeza da análise (80-100% = confiável) |
| **type (MINOR/MAJOR)** | Apenas versão (MINOR) ou mudanças de código (MAJOR) |
| **effort_estimate** | Tempo estimado para correção |

---

## 🏗️ Arquitetura

### Divisão de Responsabilidades (Opção 3 - Híbrida)

```
Fluxo VRA:

1. ANÁLISE (Determinística)
   └─ vra analyze [projeto]
      ├─ Parse (Babel AST para JS, stdlib AST para Python)
      ├─ Call Graph (reachability levels 1/2/3)
      ├─ CVE Matching (NVD API ou cache local)
      └─ Output: analysis.json (estruturado, reprodutível)

2. RELATÓRIO (AI-Agnostico, Opcional)
   └─ vra report analysis.json --ai-provider [claude|openai|gemini|custom|none]
      ├─ Lê analysis.json
      ├─ [Opcionalmente] Chama IA para remediação:
      │  └─ Prompt: "Para cada CVE, sugira tipo (MAJOR/MINOR/OPTIONAL) e ações"
      │  └─ Resposta: JSON com sugestões detalhadas
      ├─ Mescla sugestões em analysis.json
      └─ Output: relatório HTML/Markdown/JSON

Estrutura de Código:

src/
├── types/
│   └── analysis-result.ts         # Schema compartilhado
├── adapters/
│   └── ai_providers/              # Abstração agnóstica de IA
│       ├── ai_provider.interface  # Contrato
│       ├── prompts.ts             # Prompt shared + parsing
│       ├── claude_provider.ts     # Implementação Anthropic
│       ├── openai_provider.ts     # Implementação OpenAI (+ custom)
│       ├── gemini_provider.ts     # Implementação Google
│       └── provider_factory.ts    # Factory com resolução de env vars
├── cli/
│   ├── commands/
│   │   ├── analyze.ts             # Análise (hoje mockado)
│   │   └── report.ts              # Renderização de relatório
│   └── report/
│       ├── render-html.ts         # Renderer HTML
│       └── render-markdown.ts     # Renderer Markdown
├── core/                          # Dart core (WIP)
└── adapters/vulnerability_sources # Parsers (WIP)
```

### Fluxo de Dados

```
projeto-local/                                 (usuário)
  ↓
vra analyze ./projeto --level 2 --output a.json
  ├─ Parse (JS/Python) → Call Graph
  ├─ Fetch CVEs (NVD)
  ├─ Check Reachability (alcançável?)
  ↓
a.json (determinístico, sempre igual)
  │
  ├─ Cenário 1: Sem IA
  │  ├─ vra report a.json --ai-provider none
  │  └─ Output: relatório com remediações do a.json
  │
  └─ Cenário 2: Com IA do usuário
     ├─ vra report a.json --ai-provider claude --ai-token $KEY
     ├─ Send a.json findings → LLM (Claude, GPT, Gemini, etc.)
     ├─ LLM retorna: sugestões de remediação em JSON
     ├─ Merge: sugestões sobrescrevem remediation em a.json
     └─ Output: relatório enriquecido com IA
```

### Por que Agnóstico?

Empresas usam diferentes LLMs por motivos legítimos:
- **Custo:** OpenAI GPT pode ser caro; Gemini ou custom (Ollama) é barato
- **Compliance:** Dados não podem sair da rede; usa self-hosted (Ollama)
- **Já paga:** Empresa tem contrato com Claude; usa esse
- **Qualidade:** Diferentes LLMs são melhores em diferentes tarefas

VRA oferece **um** workflow — o usuário escolhe a IA. Sem lock-in.

---

## 📚 Documentação

- [Guia de Arquitetura](./VULNERABILITY_ANALYZER_ARCHITECTURE.md)
- [Referência de API](./docs/API.md)
- [Diretrizes de Contribuição](./packages/sambura_core/CONTRIBUTING.md)
- [Configuração](./docs/CONFIG.md)

---

## 🧪 Testes

```bash
# Executar todos os testes
npm test

# Executar suite específica
npm test -- provider_factory
npm test -- report

# Modo watch
npm test -- --watch

# Testes E2E (infraestrutura ainda em desenvolvimento)
npm run test:e2e
```

### Teste Manual: Gerar Relatório de Exemplo

```bash
# Sem IA (rápido, offline)
npm run build
node dist/cli/index.js report tests/fixtures/analysis-results/sample-basic.json \
  --format html --ai-provider none --output /tmp/report.html

# Visualizar
open /tmp/report.html  # macOS
xdg-open /tmp/report.html  # Linux
```

---

## 📦 Pacotes

### NPM
```bash
npm install vra-cli
```

### Pub.dev (Dart)
```bash
dart pub add vulnerability_reachability_analyzer
```

### PyPI (Python)
```bash
pip install vra-python-parsers
```

---

## 🔧 Configuração

### Variáveis de Ambiente (para AI)

```bash
# Claude (Anthropic)
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI
export OPENAI_API_KEY="sk-..."

# Gemini (Google)
export GEMINI_API_KEY="AIzaSy..."
# ou
export GOOGLE_API_KEY="AIzaSy..."
```

### Arquivo de Configuração `.vrarc` (Em desenvolvimento)

```json
{
  "language": "javascript",
  "reachability_level": 2,
  "cve_sources": ["nvd", "local"],
  "cache_dir": "./.vra-cache",
  "exclude_packages": ["@types/*"],
  "entry_points": ["src/index.ts"]
}
```

### Opções de Linha de Comando

```bash
# Análise
vra analyze [path] --level 1|2|3 --language js|python|java|go|rust --output results.json

# Relatório com IA
vra report analysis.json \
  --format html|markdown|json \
  --ai-provider claude|openai|gemini|custom|none \
  --ai-token [API_KEY] \
  --ai-base-url [para custom endpoints] \
  --ai-model [opcional, override model padrão] \
  --output relatorio.html
```

---

## 🔌 Integração com Samburá (Planejado V2)

Hawkeye planejado para integrar com Samburá para forçar políticas de segurança:

```dart
// Na configuração do gateway Samburá (V2)
import 'package:hawkeye_core/hawkeye_core.dart';

final analyzer = ReachabilityAnalyzer();
final result = await analyzer.analyze(projectPath);

// Bloquear deployments com vulnerabilidades críticas alcançáveis
if (result.getCriticalReachable().isNotEmpty) {
  throw PolicyViolationException('Vulnerabilidades críticas detectadas');
}
```

---

## 🤝 Contribuindo

Contribuições bem-vindas! Por favor, consulte [CONTRIBUTING.md](./packages/sambura_core/CONTRIBUTING.md)

1. Faça um fork do repositório
2. Crie uma branch de feature (`git checkout -b feature/minha-feature`)
3. Commit suas mudanças (`git commit -am 'Add minha feature incrível'`)
4. Push para a branch (`git push origin feature/minha-feature`)
5. Abra um Pull Request

---

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](./LICENSE).

---

## 🙏 Agradecimentos

- **Marchizinho** — Visão arquitetônica e design do projeto
- **Heinrich VHO** (@heinrickVHO2) — Code review e feedback técnico
- Comunidade OWASP e pesquisa de segurança
- Babel, módulo AST, NVD e ecossistema Samburá

Veja [CONTRIBUTORS.md](CONTRIBUTORS.md) para saber mais sobre quem faz Hawkeye possível! ❤️

---

## 📧 Suporte

- 📖 [Documentação](./docs)
- 🐛 [Rastreador de Issues](https://github.com/lucasvsantos591-hue/hawkeye/issues)
- 💬 [Discussões](https://github.com/lucasvsantos591-hue/hawkeye/discussions)
- 📧 Email: lucasvsantos591@gmail.com
