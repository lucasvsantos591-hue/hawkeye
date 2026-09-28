# Vulnerability Reachability Analyzer (VRA)

> **Validação Inteligente de CVEs** | Vá além do scanning baseado em versões para determinar se uma vulnerabilidade é realmente explorável no seu código.

## 🎯 O Problema

Ferramentas SCA tradicionais (Software Composition Analysis) marcam qualquer versão de pacote com uma CVE conhecida como vulnerável—**mesmo que seu código nunca use a função vulnerável**.

**Exemplo:**
```javascript
// Seu código
import axios from 'axios'; // CVE-2023-XXXX em axios < 1.4.0

export function fetchData() {
  // Usa apenas métodos seguros
  return axios.get('/api/data');
}
```

Scanner tradicional: ⚠️ **VULNERÁVEL** (falso positivo)
VRA: ✅ **SEGURO** (função vulnerável não é chamada)

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
  "results": [
    {
      "vulnerability": {
        "cve_id": "CVE-2023-12345",
        "package": "express",
        "severity": "HIGH",
        "affected_versions": ["<4.17.1"]
      },
      "is_reachable": true,
      "reachability_level": 2,
      "confidence": 92,
      "call_chain": [
        "main",
        "setupRoutes",
        "handleRequest",
        "vulnerableFunction"
      ],
      "remediation_advice": "Atualizar express para >=4.17.1"
    },
    {
      "vulnerability": {
        "cve_id": "CVE-2023-54321",
        "package": "lodash",
        "severity": "MEDIUM",
        "affected_versions": ["<4.17.20"]
      },
      "is_reachable": false,
      "reachability_level": 1,
      "confidence": 100,
      "remediation_advice": "Nenhuma ação necessária - função vulnerável não é usada"
    }
  ]
}
```

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
