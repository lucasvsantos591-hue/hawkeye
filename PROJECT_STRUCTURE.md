# VRA Project Structure & Setup Guide

## 📦 What's Been Created

Você agora tem a estrutura completa de um **Vulnerability Reachability Analyzer** pronto para desenvolvimento!

### ✅ Arquivos Criados

#### **Core (Dart)**
```
core/
├── pubspec.yaml                 # Dependências Dart (zero-deps)
├── lib/
│   ├── models/
│   │   ├── vulnerability.dart   # Modelo de CVE/vulnerabilidade
│   │   ├── dependency.dart      # Modelo de dependências
│   │   ├── call_graph.dart      # Modelo de grafo de chamadas
│   │   └── reachability_result.dart  # Resultado da análise
│   └── ports/
│       ├── vulnerability_source.dart # Interface para CVE sources
│       ├── dependency_resolver.dart  # Interface para resolvedores
│       ├── ast_parser.dart           # Interface para parsers
│       └── storage.dart              # Interface para cache/storage
```

#### **Adapters (TypeScript + Python)**
```
adapters/
├── parsers/
│   ├── js_typescript_parser/
│   │   └── call_graph_builder.ts   # Parser Babel para JS/TS
│   └── python_parser/
│       └── call_graph_builder.py   # Parser AST para Python
└── vulnerability_sources/
    └── nvd_api_adapter.ts          # Integração com NVD API
```

#### **CLI**
```
src/cli/
├── index.ts                    # Entry point
└── commands/
    ├── analyze.ts             # Comando: vra analyze <path>
    ├── scan.ts                # Comando: vra scan <pkg> <version>
    └── report.ts              # Comando: vra report <input>
```

#### **Tests & Fixtures**
```
tests/
├── fixtures/
│   └── sample_projects/
│       ├── js_vulnerable_app/    # App JS com vuln exploável
│       ├── js_safe_app/          # App JS sem exploração
│       ├── python_vulnerable_app/# App Python vulnerável
│       └── python_safe_app/      # App Python seguro
└── unit/
    └── call_graph_builder.test.ts # Testes de parser
```

#### **Configuração**
```
Project Root
├── Makefile                  # Comandos de automação
├── docker-compose.yml        # Services de dev (Redis, mock-NVD)
├── package.json              # Dependências Node.js
├── pyproject.toml            # Configuração Python
├── tsconfig.json             # Configuração TypeScript
├── requirements.txt          # Deps Python
├── .gitignore                # Git ignore patterns
├── README.md                 # Documentação principal
└── PROJECT_STRUCTURE.md      # Este arquivo
```

---

## 🚀 Próximos Passos

### 1. **Abrir no VS Code**

```bash
# Abrir projeto no VS Code
code /home/usuario/vra-project

# Ou você pode usar o VS Code direto e abrir a pasta
```

### 2. **Instalar Dependências**

```bash
cd /home/usuario/vra-project
make setup
```

Isso vai:
- ✅ Instalar deps Dart (`dart pub get`)
- ✅ Instalar deps Node.js (`npm install`)
- ✅ Instalar deps Python (`pip install -r requirements.txt`)

### 3. **Iniciar Ambiente de Desenvolvimento**

```bash
# Iniciar serviços (Docker required)
make dev-up

# Ou assistir mudanças em tempo real
make watch
```

### 4. **Rodar Testes**

```bash
# Todos os testes
make test

# Teste específico
make test-core
make test-cli
make test-e2e
```

---

## 🎯 Fase 1: MVP (Próximas Semanas)

### Core Features a Implementar

- [ ] **Dependency Resolution**
  - [x] Modelo `Dependency` + `DependencyTree`
  - [ ] Implementar `NPMResolver` (package.json parser)
  - [ ] Implementar `PythonResolver` (requirements.txt parser)

- [ ] **Call Graph Building**
  - [x] Modelo `CallGraph` + `CallGraphNode`
  - [x] Parser JavaScript/TypeScript (básico)
  - [x] Parser Python (básico)
  - [ ] Testes e integração

- [ ] **Vulnerability Analysis**
  - [x] Modelo `Vulnerability`
  - [x] Adaptador NVD API
  - [ ] Cache SQLite local
  - [ ] Implementar `ReachabilityAnalyzer` (Level 1, 2)

- [ ] **CLI Interface**
  - [x] Estrutura básica (yargs)
  - [ ] Implementar comando `analyze`
  - [ ] Implementar comando `scan`
  - [ ] Formatadores (JSON, HTML, SARIF)

- [ ] **Integration with Samburá**
  - [ ] REST API adapter
  - [ ] Policy enforcement hooks

---

## 📊 Arquitetura de Dados

```
CVE Database (NVD)
    ↓
[Cache Local - SQLite]
    ↓
[Vulnerability Analyzer]
    ↑
    ├─→ [Dependency Resolver] ← package.json / requirements.txt
    │
    ├─→ [AST Parser] ← Source code
    │
    └─→ [Call Graph Builder] ← Extract functions & calls
    
    ↓
[Reachability Engine]
    ├─ Level 1: Import detection
    ├─ Level 2: Call chain analysis
    └─ Level 3: Data flow tracking
    
    ↓
[Report Generator]
    ├─ JSON
    ├─ HTML
    └─ SARIF (CI/CD standard)
```

---

## 🧪 Estratégia de Testes

### Unit Tests
- Cada adapter testado isoladamente
- Mock de data sources
- Fixtures de proyetos reales

### Integration Tests
- Teste pipeline completo (entrada → análise → saída)
- Com dados reais (NVD API)
- Com projetos de fixture

### E2E Tests
- Teste CLI commands
- Relatórios gerados corretamente
- Integração Samburá

---

## 🔐 Segurança

- ✅ Zero external deps no core Dart
- ✅ AST parsing (não eval de código)
- ✅ Rate limiting para NVD API
- ✅ Caching para respeitar limites da API
- 🔲 Validação de input (TODO)
- 🔲 Sanitização de relatórios (TODO)

---

## 📈 Roadmap

### Phase 1 (MVP)
- ✅ Arquitetura base
- [ ] Nivel 1 + 2 de reachability
- [ ] CLI básica
- [ ] Documentação

### Phase 2
- [ ] Data flow / taint analysis (Level 3)
- [ ] Suporte Java / Go
- [ ] Dashboard web
- [ ] Integração Samburá avançada

### Phase 3
- [ ] Machine learning para falsos positivos
- [ ] GraphQL API
- [ ] Multi-tenant SaaS

---

## 💡 Dicas para Desenvolvimento

### Ambiente Local

1. **Python virtual env** (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate no Windows
```

2. **Watch mode** para desenvolviment o rápido:
```bash
make watch  # Reconstrói automaticamente
```

3. **Debug mode**:
```bash
vra analyze . --debug --verbose
```

### Testing
- Testes usam fixtures em `tests/fixtures/sample_projects/`
- Adicione novo projeto de teste quando cobrir novo caso
- Coverage target: 80%+

### Code Style
```bash
make format   # Formata código
make lint     # Análise estática
```

---

## 🆘 Troubleshooting

### Erro: "dart not found"
```bash
# Instale Dart SDK
# macOS
brew install dart

# Linux
sudo apt-get install dart

# ou via https://dart.dev/get-dart
```

### Erro: "npm packages not found"
```bash
make clean-all
make setup
```

### Erro: Docker não disponível
- `dev-up` e `dev-down` usam Docker
- Você pode testar localmente sem Docker (cache será em-memory)

---

## 📚 Referências Úteis

- **Babel AST**: https://babel.dev/docs/en/babel-types
- **Python AST**: https://docs.python.org/3/library/ast.html
- **NVD API**: https://nvd.nist.gov/developers/api
- **SARIF Format**: https://sarifweb.azurewebsites.net/
- **Reachability Analysis**: https://en.wikipedia.org/wiki/Reachability

---

**Desenvolvido com ❤️ para segurança de software**
