# 🔄 Fluxo de Uso do Hawkeye

## Diagrama do Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    OUTRO USUÁRIO CLONA HAWKEYE                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  git clone https://github.com/lucasvsantos591-hue/hawkeye.git   │
│  cd hawkeye                                                       │
│  npm install && npm run build                                     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              APONTA PARA UM PROJETO PARA ANALISAR                │
│                   (Qualquer projeto Node.js)                     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  node ./dist/cli/index.js analyze /caminho/do/projeto             │
│                                                                   │
│  O QUE ACONTECE:                                                  │
│  ✓ Lê package.json do projeto                                   │
│  ✓ Detecta TODAS as dependências automaticamente                │
│  ✓ Cross-reference com banco de CVEs                            │
│  ✓ Analisa código-fonte (AST + taint analysis)                  │
│  ✓ Determina se vulnerabilidades são reachable                  │
│  ✓ Calcula confiança de cada achado                             │
│                                                                   │
│  RESULTADO: findings.json                                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│         GERA RELATÓRIO (escolhe formato desejado)                │
│                                                                   │
│  node ./dist/cli/index.js report findings.json \                 │
│    --enrichment \                                                 │
│    --format [html|docx|markdown|json]                            │
│                                                                   │
│  O QUE ACONTECE:                                                  │
│  ✓ Enriquece com CISA KEV (vulnerabilidades exploradas)         │
│  ✓ Enriquece com FIRST EPSS (probabilidade exploração)          │
│  ✓ Calcula Priority Score (0-100)                               │
│  ✓ Formata para o tipo escolhido                                │
│                                                                   │
│  RESULTADO: report.html / report.docx / report.md               │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│               VISUALIZA/COMPARTILHA O RELATÓRIO                  │
│                                                                   │
│  • HTML → Abre no navegador, vê tudo interativo                 │
│  • DOCX → Abre no Word, imprime, envia por email                │
│  • JSON → Integra com ferramentas externas/CI-CD                │
└─────────────────────────────────────────────────────────────────┘
```

## Exemplo Real Passo a Passo

### Usuário quer analisar seu projeto `my-app`

```bash
# PASSO 1: Clonar Hawkeye (primeira vez só)
$ git clone https://github.com/lucasvsantos591-hue/hawkeye.git
$ cd hawkeye
$ npm install
$ npm run build

# PASSO 2: Analisar o projeto dele
$ node ./dist/cli/index.js analyze ~/my-app --output findings.json

📊 Analyzing ~/my-app
✓ Found 45 dependencies
✓ Detected 12 vulnerable packages
✓ Scanned 150 source files
✓ Analysis complete: 8 vulnerabilities (3 reachable, 5 not reachable)
✓ Results saved to findings.json

# PASSO 3: Gerar relatório HTML
$ node ./dist/cli/index.js report findings.json --enrichment --format html --output report.html

📄 Generating HTML report from findings.json...
🔍 Enriching findings with CVE context (CISA KEV + FIRST EPSS)...
✅ Report saved to: report.html

# PASSO 4: Abrir no navegador
$ open report.html
# (ou xdg-open report.html no Linux)
```

## O que o Usuário VÊ no Relatório?

Para **cada vulnerabilidade encontrada**:

```
┌─────────────────────────────────────────────────┐
│ CVE-2018-16487 - lodash@4.17.15    [HIGH]      │
├─────────────────────────────────────────────────┤
│                                                  │
│ 📌 Versões Afetadas: <4.17.19                  │
│ 🎯 Reachability Confidence: 95%                │
│                                                  │
│ 📍 Cadeia de Exploração                        │
│    Entrada: POST /api/process-data             │
│    1. src/index.js:main                        │
│    2. src/routes/index.js:setupRoutes()        │
│    3. src/handlers/data.js:processUserData()   │
│    4. _.defaultsDeep(data.items, ...)          │
│                                                  │
│ ✅ Por que é explorável neste código           │
│    Prototype pollution em lodash.defaultsDeep  │
│    usado diretamente com entrada do usuário    │
│                                                  │
│ 🔍 CVE Enrichment & Priority Analysis          │
│    Priority Score: 68/100 → HIGH               │
│    EPSS Score: 7.8/100 (p92)                   │
│    Known Exploitation: ✅ YES (CISA KEV)       │
│    Priority Reasoning: High EPSS + Exploited   │
│                                                  │
│ 💡 Correção                                    │
│    Atualizar lodash para 4.17.19 ou posterior │
│    Comando: npm install lodash@5.0.0 --save   │
│    Esforço: 2–4 h                              │
│    Quebra de Compatibilidade: Não              │
│                                                  │
│    Ajustes Necessários:                        │
│    • npm install lodash@5.0.0 --save           │
│    • Validar entrada com zod .strict()         │
│    • Substituir _.assign() por Object.assign() │
│                                                  │
└─────────────────────────────────────────────────┘
```

## Opções Disponíveis

### analyze command

```bash
node ./dist/cli/index.js analyze <caminho> [opções]

Opções:
  --output, -o <path>    Caminho para salvar findings.json
  --level, -l <number>   Nível de análise (1, 2, 3)
                         1 = imports apenas (rápido)
                         2 = reachability (padrão)
                         3 = taint analysis (completo, lento)
```

### report command

```bash
node ./dist/cli/index.js report <findings.json> [opções]

Opções:
  --format, -f <type>    Tipo de saída:
                         html (padrão) - web interativo
                         docx - Word profissional
                         markdown - documentação
                         json - dados puros
  
  --output, -o <path>    Caminho do arquivo de saída
  
  --enrichment          Adicionar CISA KEV + FIRST EPSS
                        (recomendado, ativa Priority Score)
  
  --ai-provider         Usar IA para melhorar remediações
                        claude, openai, gemini, custom
  
  --ai-token            Token do provedor de IA
```

## Resposta à Pergunta Original

**"Ele baixaria esse repositório pra máquina, e aí? Quando ele executasse, ele teria que passar o outro projeto como referência, e quais CVEs ele quer ver?"**

**Resposta:**

1. ✅ Sim, ele clona o repositório
2. ✅ Ele não precisa escolher **QUAIS CVEs** - o Hawkeye detecta **TODAS automaticamente**
3. ✅ Ele apenas aponta para o projeto com `analyze /caminho/do/projeto`
4. ✅ O Hawkeye faz toda a detecção, análise e enriquecimento sozinho
5. ✅ Ele recebe um relatório completo com tudo já priorizado por risco

**O usuário não precisa saber:**
- Quais CVEs existem
- Como detectá-los
- Como enriquecê-los

**Tudo é automático!** 🎯
