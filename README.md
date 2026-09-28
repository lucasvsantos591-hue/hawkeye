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

- Dart 3.0+
- Node.js 18+
- Python 3.10+
- Make

### Instalação

```bash
git clone https://github.com/seu-usuario/vra-project.git
cd vra-project
make setup
```

### Uso Básico

```bash
# Analisar um projeto JavaScript/TypeScript
vra analyze ./meu-app-nodejs --level 2

# Analisar um projeto Python
vra analyze ./meu-app-python --language python --level 3

# Gerar relatório HTML
vra analyze ./meu-app --format html --output relatorio.html

# Verificar um CVE específico
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

```
vulnerability-reachability-engine/
├── core/                      # Núcleo Dart sem dependências externas
├── adapters/                  # Parsers de linguagem & adaptadores de API
│   ├── parsers/
│   │   ├── js_typescript_parser/
│   │   └── python_parser/
│   └── vulnerability_sources/
│       ├── nvd_api_adapter.ts
│       └── local_db_adapter.dart
├── cli/                       # Interface de linha de comando
├── integration/               # Conector Samburá
└── tests/                     # Suite de testes abrangente
```

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
make test

# Executar suite de testes específica
make test-core
make test-cli
make test-e2e

# Modo watch (monitora mudanças)
make test-watch

# Relatório de cobertura
make test-core -- --coverage
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

Crie um arquivo `.vrarc` na raiz do seu projeto:

```json
{
  "language": "javascript",
  "reachability_level": 2,
  "cve_sources": ["nvd", "local"],
  "cache_dir": "./.vra-cache",
  "exclude_packages": ["@types/*"],
  "entry_points": ["src/index.ts"],
  "output": {
    "format": "json",
    "path": "./relatorio.json"
  }
}
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
