# Vulnerability Reachability Analyzer (VRA)

> **Validação Inteligente de CVEs** | Vá além do scanning baseado em versões para determinar se uma vulnerabilidade é realmente explorável no seu código.

## 🎯 O Problema

### Scanners SCA Tradicionais: "Versão = Risco"

Ferramentas SCA (Software Composition Analysis) fazem apenas **matching de versões**:
- ✅ **Detectam:** Você tem `axios@1.3.5` e existe CVE-2023-XXXX em `axios < 1.4.0`
- ❌ **Não validam:** Se seu código usa a função vulnerável
- ❌ **Não verificam:** Se o código pode alcançar aquele ponto vulnerável

Elas então correlacionam EPSS (Exploit Prediction Scoring System) + KEV (Known Exploited Vulnerabilities) para calcular criticidade. **Resultado: 80-90% falsos positivos**—vulnerabilidades que nunca vão impactar você.

**Consequência:** Seu time gasta horas auditando vulnerabilidades que não são exploráveis, ou deprioritiza as que realmente importam.

### VRA: Análise de Reachability (Alcançabilidade)

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

### Com VRA (Análise de Reachability)
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

## ✨ Características

### 🔍 Três Níveis de Análise de Alcançabilidade

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

- **JavaScript/TypeScript** (via Babel AST)
- **Python** (via módulo AST)
- **Java, Go, Rust** (roadmap)

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
git clone https://github.com/seu-usuario/vra-project.git
cd vra-project
npm install
npm run build
```

### Uso Básico: Workflow em Dois Passos

VRA separa análise determinística de enhancement com IA:

**1️⃣ Análise (determinística, sem IA)**
```bash
# Gera JSON estruturado com vulnerabilidades e alcançabilidade
vra analyze ./meu-app --level 2 --output analysis.json
```

**2️⃣ Relatório (com IA agnóstica opcional)**
```bash
# Sem IA: apenas estrutura as recomendações do analysis.json
vra report analysis.json --format html --output relatorio.html --ai-provider none

# Com Claude (requer ANTHROPIC_API_KEY ou --ai-token)
vra report analysis.json --format html --ai-provider claude --output relatorio-claude.html

# Com OpenAI (requer OPENAI_API_KEY ou --ai-token)
vra report analysis.json --format html --ai-provider openai --output relatorio-gpt.html

# Com Gemini (requer GEMINI_API_KEY ou GOOGLE_API_KEY ou --ai-token)
vra report analysis.json --format html --ai-provider gemini

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

## 🔌 Integração com Samburá

VRA pode se integrar com Samburá para forçar políticas:

```dart
// Na configuração do gateway Samburá
import 'package:vra_core/vra_core.dart';

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

- Construído com inspiração da comunidade OWASP e pesquisa de segurança
- Powered by Babel, módulo AST, e NVD
- Parte do ecossistema Samburá para cadeias de suprimento de software seguro

---

## 📧 Suporte

- 📖 [Documentação](./docs)
- 🐛 [Rastreador de Issues](https://github.com/lucasvsantos591-hue/vra-project/issues)
- 💬 [Discussões](https://github.com/lucasvsantos591-hue/vra-project/discussions)
- 📧 Email: vra@example.com
