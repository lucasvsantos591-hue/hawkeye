# 🎯 Hawkeye V2 Roadmap 🚀

## Visão Geral

V1 entrega **análise agnóstica e determinística** com **IA opcional**. V2 traz **integração com repositórios** e **seleção granular de CVEs**.

**Lema**: Um tiro, um alvo. Sem desperdício.

## Features V2

### 1. 🔗 Scan Repo com CVE Selecionado

**Problema**: Usuário precisa clonar o repositório localmente, passar como parâmetro, e depois rodar análise em TODAS as vulnerabilidades.

**Solução**: Um comando que:
- Baixa repositório direto (GitHub/GitLab)
- Filtra para CVEs específicas (user seleciona)
- Roda análise apenas naquelas
- Gera relatório focused

**Comando Proposto**:
```bash
vra scan-repo \
  --repo https://github.com/user/projeto \
  --cves CVE-2023-12345,CVE-2023-54321,CVE-2024-99999 \
  --branch main \
  --ai-provider claude \
  --ai-token $KEY \
  --output report-focused.html
```

**Fluxo Interno**:
1. Clone/fetch do repo (temporário)
2. Parse manifestos (package.json, requirements.txt, pom.xml, go.mod, etc.)
3. Filter CVEs: apenas as passadas em `--cves`
4. Análise de reachability (levels 1/2/3)
5. [Opcional] Enriquecer com IA
6. Gerar relatório
7. Limpar diretório temporário

**Implementação**:
- `src/cli/commands/scan-repo.ts` (novo)
- `src/adapters/repo-source/` (novo)
  - `github_adapter.ts` - Clone via GitHub API ou git CLI
  - `gitlab_adapter.ts` - Clone via GitLab API
  - `local_adapter.ts` - Suporta local paths também
- `src/adapters/cve-filter/` (novo)
  - Filtra manifestos e apenas procura pelas CVEs requested

---

### 2. 📋 Integração com GitHub/GitLab Issues/PRs

**Problema**: Vulnerabilidades descobertas mas o resultado fica só em um relatório. Time não vê no seu workflow.

**Solução**: VRA pode:
- Postar resultado como **GitHub Issue** automaticamente
- Criar **Pull Request** com sugestões de fix (se MINOR/auto-fixable)
- Comentar em **PRs existentes** se detectar vulnerabilidades

**Comando Proposto**:
```bash
vra scan-repo \
  --repo https://github.com/user/projeto \
  --cves CVE-2023-12345 \
  --ai-provider claude \
  --post-github-issue \
  --github-token $GITHUB_TOKEN \
  --issue-labels security,reachable \
  --issue-assignees @usuario1,@usuario2

# Ou criar PR com fix sugerido (se simples)
vra scan-repo \
  --repo https://github.com/user/projeto \
  --cves CVE-2023-12345 \
  --create-pr \
  --pr-title "Security: Fix CVE-2023-12345 in express" \
  --github-token $GITHUB_TOKEN
```

**Implementação**:
- `src/adapters/github-integration/` (novo)
  - Postar issue
  - Criar PR
  - Comentar em PR existente
- `src/cli/commands/scan-repo.ts` (expansão)
  - `--post-github-issue`, `--create-pr`, `--pr-draft`

---

### 3. 🔄 CI/CD Integration

**Problema**: VRA é manual. Rodas quando lembras.

**Solução**: Integração automática em CI/CD

**Exemplos**:

**GitHub Actions**:
```yaml
name: VRA Security Check
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm install -g vra-cli
      - run: |
          vra analyze . --level 2 --output analysis.json
          vra report analysis.json \
            --format json \
            --ai-provider claude \
            --ai-token ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: analysis.json
```

**GitLab CI**:
```yaml
security_scan:
  image: node:18
  script:
    - npm install -g vra-cli
    - vra analyze . --level 2 --output analysis.json
    - vra report analysis.json --format json --ai-provider openai --ai-token $OPENAI_API_KEY
  artifacts:
    paths:
      - analysis.json
```

**Implementação**:
- Documentação detalhada em `docs/CI_CD.md`
- Templates prontos em `examples/ci-cd/`
- Suporte a saídas estruturadas (JSON, SARIF para GitHub Code Scanning)

---

### 4. 🏢 Enterprise Features

#### a) SBOM (Software Bill of Materials) Export
```bash
vra analyze . --format sbom --output sbom.json
# Gera SBOM padrão CycloneDX com vulnerabilidades anotadas
```

#### b) Compliance Reports
```bash
vra analyze . --format compliance --template cis,pci-dss,nist
# Relatório aderência a frameworks de compliance
```

#### c) Multi-repo Dashboard
```bash
vra dashboard --repos ./repos.csv --ai-provider claude
# Agregação visual de vulnerabilidades across múltiplos projetos
```

---

### 5. 🔒 Segurança & Privacy

#### a) Cache Encriptado
- Armazenar CVE cache localmente (offline-first)
- Encriptar com chave do usuário

#### b) Proxy Support
- Suportar HTTPS proxies corporativos
- Variáveis: `HTTP_PROXY`, `HTTPS_PROXY`

#### c) Audit Log
- Registrar quem rodou análise, quando, com quais CVEs
- Para compliance e auditoria interna

---

### 6. 🎨 UX Melhorias

#### a) Interactive CLI
```bash
$ vra
? Qual é a ação desejada?
  > analyze
    report
    scan-repo
    dashboard
```

#### b) Progress Bar & Streaming
- Mostrar progresso durante análise grande
- Streaming de resultados em tempo real para `--watch` mode

#### c) Diff Reports
```bash
vra diff report-old.html report-new.html
# Mostra o que mudou entre duas análises
```

---

## Priorização V2

### 🔴 Crítico (faz maior diferença)
1. `scan-repo` com GitHub/GitLab clone
2. `--post-github-issue` (o resultado fica visível no workflow)

### 🟡 Importante
3. CI/CD templates + docs
4. SBOM export (enterprise/compliance)

### 🟢 Nice-to-have
5. Interactive CLI
6. Dashboard multi-repo
7. Diff reports

---

## Timeline Estimado

- **V2.0** (Mês 1-2): scan-repo + GitHub integration + CI/CD docs
- **V2.1** (Mês 3): SBOM, compliance reports
- **V2.2** (Mês 4+): Enterprise features (proxy, audit log, dashboard)

---

## Feedback Esperado do Time Corporate

Após testes em cenário real, esperamos feedback em:

- ✅ **Usabilidade**: Comandos intuitivos?
- ✅ **Performance**: Análise rápida o suficiente?
- ✅ **Accuracy**: Falsos positivos aceitáveis?
- ✅ **Integração**: Encaixa no workflow existente?
- ✅ **Segurança**: Está seguro para dados corporativos?
- ✅ **Escalabilidade**: Roda em repos grandes?
- ✅ **Feature priority**: Qual V2 feature é mais urgente?

---

## Links
- **Repo**: https://github.com/lucasvsantos591-hue/vra-project
- [V1 README](README.md) - Documentação atual
- [Testing Guide](TESTING_GUIDE.md) - Como testar V1 antes de V2
- **Issues**: https://github.com/lucasvsantos591-hue/vra-project/issues
