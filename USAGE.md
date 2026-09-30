# 🎯 Hawkeye - Guia de Uso

Análise de alcançabilidade de vulnerabilidades em projetos Node.js.

## 🚀 Instalação e Setup

```bash
# Clonar repositório
git clone https://github.com/lucasvsantos591-hue/hawkeye.git
cd hawkeye

# Instalar dependências
npm install

# Compilar projeto
npm run build
```

## 📊 Fluxo Básico de Análise

### Passo 1: Analisar um Projeto

```bash
node ./dist/cli/index.js analyze /caminho/do/projeto --output findings.json
```

**Exemplo prático:**

```bash
# Analisar um projeto local
node ./dist/cli/index.js analyze ~/meu-app --output findings.json

# Opções:
# --output, -o     Caminho para salvar resultados JSON
# --level, -l      Nível de análise: 1 (imports), 2 (reachability), 3 (taint)
```

**O que o Hawkeye faz automaticamente:**

1. ✅ Lê o `package.json` do projeto
2. ✅ Identifica todas as dependências
3. ✅ Faz cross-reference com banco de dados de CVEs
4. ✅ Analisa o código-fonte com AST parsing
5. ✅ Detecta se vulnerabilidades são reachable
6. ✅ Calcula nível de confiança para cada achado

### Passo 2: Gerar Relatório

```bash
node ./dist/cli/index.js report findings.json --enrichment --format html --output report.html
```

**Opções de formato:**

```bash
# HTML - Para visualização web
node ./dist/cli/index.js report findings.json --enrichment --format html --output report.html

# DOCX - Para Word/compartilhamento profissional
node ./dist/cli/index.js report findings.json --enrichment --format docx --output report.docx

# Markdown - Para documentação
node ./dist/cli/index.js report findings.json --enrichment --format markdown --output report.md

# JSON - Para automação/integração CI/CD
node ./dist/cli/index.js report findings.json --enrichment --format json --output report.json
```

## 🔍 Entendendo os Resultados

### Níveis de Alcançabilidade

| Nível | Significado | Risco | Ação |
|-------|-------------|-------|------|
| **1** | Import detectado | ✅ Baixo | Monitorar |
| **2** | Função vulnerável alcançável | 🟡 Médio | Priorizar |
| **3** | Taint: dados do usuário alcançam vulnerabilidade | 🔴 Alto | Corrigir imediatamente |

### Priority Score (0-100)

Baseado em três fatores:

- **EPSS Score** (40% peso) - Probabilidade de exploração nos próximos 30 dias
- **CISA KEV** (30% peso) - Se está sendo explorada na prática
- **Reachability** (30% peso) - Se é alcançável no seu código

**Exemplo:**
```
Priority = (EPSS × 0.4) + (CISA_KEV × 0.3) + (Reachability × 0.3)

Se EPSS=7.5, CISA=explorado(30), Reachability=95% confiança:
Priority = (7.5 × 0.4) + 30 + (95 × 0.3) = 3 + 30 + 28.5 = 61.5 → HIGH
```

## 📁 Exemplo: Analisar um Projeto Completo

```bash
# 1. Navegar para projeto
cd ~/my-project

# 2. Gerar análise
/path/to/hawkeye/dist/cli/index.js analyze . --output analysis.json

# 3. Visualizar resultados
/path/to/hawkeye/dist/cli/index.js report analysis.json --enrichment --format html --output security-report.html

# 4. Abrir relatório
open security-report.html
```

## 🔧 Integrando no CI/CD

### GitHub Actions

```yaml
name: Security Analysis

on: [push, pull_request]

jobs:
  hawkeye:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '18'
      
      - name: Clone Hawkeye
        run: git clone https://github.com/lucasvsantos591-hue/hawkeye.git hawkeye-temp
      
      - name: Build Hawkeye
        run: cd hawkeye-temp && npm install && npm run build
      
      - name: Run Analysis
        run: |
          cd hawkeye-temp
          node ./dist/cli/index.js analyze .. --output findings.json
          node ./dist/cli/index.js report findings.json --enrichment --format html --output ../report.html
      
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: report.html
```

## 🎯 Casos de Uso

### Caso 1: Análise Única de um Projeto

```bash
node ./dist/cli/index.js analyze ~/proj --output findings.json
node ./dist/cli/index.js report findings.json --enrichment --format html
```

**Resultado:** Relatório HTML mostrando todas as vulnerabilidades detectadas.

### Caso 2: Monitorar Mudanças em CI/CD

```bash
# Executar no PR
node ./dist/cli/index.js analyze . --output current.json

# Comparar com baseline (em script externo)
# Se novo CVE for detectado, falhar o build
```

### Caso 3: Auditoria Profissional

```bash
# Gerar relatório completo
node ./dist/cli/index.js analyze /projeto --output findings.json
node ./dist/cli/index.js report findings.json --enrichment --format docx --output audit-report.docx

# Enviar para stakeholders
```

## ❓ FAQ

**P: Como filtro para ver apenas HIGH/CRITICAL?**
R: O HTML/DOCX já separa por severity automaticamente. Você pode abrir o JSON e filtrar programaticamente.

**P: Posso analisar TODOS os meus projetos?**
R: Sim! Execute o comando de análise em cada projeto:
```bash
for dir in ~/projects/*; do
  node hawkeye/dist/cli/index.js analyze "$dir" --output "$dir/findings.json"
done
```

**P: E se eu quiser comparar antes/depois de uma correção?**
R: Salve `findings-before.json` e `findings-after.json`, depois compare:
```bash
# Gerar dois relatórios e comparar manualmente
node ./dist/cli/index.js report findings-before.json --format json > before.json
node ./dist/cli/index.js report findings-after.json --format json > after.json
# Usar diff tools ou scripts customizados
```

**P: Como integro com meu sistema de tickets (Jira, Linear)?**
R: Use o formato JSON e crie um script custom:
```bash
node ./dist/cli/index.js report findings.json --format json > report.json
# Seu script customizado lê report.json e cria tickets
```

## 📞 Suporte

Para problemas ou dúvidas:
- GitHub Issues: https://github.com/lucasvsantos591-hue/hawkeye/issues
- Email: support@hawkeye.dev

---

**Hawkeye V2.1** - Precision Vulnerability Reachability Analysis
