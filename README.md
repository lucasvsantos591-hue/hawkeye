# 🎯 Hawkeye

[![CI Status](https://github.com/lucasvsantos591-hue/hawkeye/actions/workflows/ci.yml/badge.svg)](https://github.com/lucasvsantos591-hue/hawkeye/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Node.js 20+](https://img.shields.io/badge/Node.js-20+-green)](https://nodejs.org/)
![Ecossistemas](https://img.shields.io/badge/ecossistemas-npm%20%7C%20Python%20%7C%20Maven%20%7C%20Gradle-blue)

**Análise de vulnerabilidades em dependências, com reachability.**

O Hawkeye lê as versões **realmente instaladas** no seu repositório (lockfiles, árvore do Maven/Gradle),
consulta as vulnerabilidades conhecidas de cada uma e mostra **quais o seu código de fato usa**, com
arquivo, linha e funções/classes chamadas. Assim o time corrige primeiro o que é alcançável e explorado de
verdade, em vez de uma lista de centenas de alertas.

> **Status: beta (v0.3.0).** Validado em repositórios reais (veja [Validação](#-validação)). Leia as
> [Limitações](#-limitações-conhecidas) antes de usar o resultado para decidir o que *não* corrigir.

---

## Sumário

- [Por que reachability](#-por-que-reachability)
- [O que é suportado](#-o-que-é-suportado)
- [Instalação](#-instalação)
- [Uso rápido](#-uso-rápido)
- [Referência da CLI](#-referência-da-cli)
- [Como funciona](#-como-funciona)
- [Entendendo o resultado](#-entendendo-o-resultado)
- [Integração com CI/CD](#-integração-com-cicd)
- [API HTTP e Docker](#-api-http-e-docker)
- [Contexto de exposição e remediação com IA](#-contexto-de-exposição-e-remediação-com-ia)
- [Configuração (variáveis de ambiente)](#-configuração-variáveis-de-ambiente)
- [Validação](#-validação)
- [Limitações conhecidas](#-limitações-conhecidas)
- [Desenvolvimento](#-desenvolvimento)
- [Roadmap](#-roadmap)

---

## 💡 Por que reachability

Scanners de dependência tradicionais (SCA) respondem *"alguma versão vulnerável está instalada?"*. Em projetos
reais a resposta é quase sempre "sim, dezenas", e a maioria desses alertas envolve pacotes que o código nem
chama: dependências só de teste, imports só de tipo, bibliotecas puxadas por ferramentas de build.

O Hawkeye responde uma pergunta mais útil: **"essa vulnerabilidade está num pacote que o meu código usa?"**

| | SCA tradicional | Hawkeye |
|---|---|---|
| Versão instalada | ✅ | ✅ (lockfile / árvore resolvida) |
| Import do pacote no código | ❌ | ✅ com arquivo:linha |
| Quais funções/classes são usadas | ❌ | ✅ (`_.template`, `yaml.load`, `XStream`) |
| Dependência transitiva → qual direta a puxa | parcial | ✅ todas, e herda a reachability da direta usada mais próxima |
| Import só de tipo / só em teste | ❌ | ✅ filtrado, com o motivo |
| Exploração ativa (CISA KEV) e probabilidade (EPSS) | às vezes | ✅ com status explícito em cada CVE, inclusive "não listada" |
| Explica cada decisão | ❌ | ✅ campos `reason` e `evidence` |

Exemplo real (app de teste com `express 4.16.0`, `lodash 4.17.10`, `axios 0.21.0`): **47 vulnerabilidades,
19 alcançáveis**. As 28 restantes são o axios importado só como tipo, o jsonwebtoken usado só em testes, etc.
Cada uma vem com o motivo.

---

## 📦 O que é suportado

| Ecossistema | De onde vêm as versões (em ordem de preferência) | Como a reachability é medida |
|---|---|---|
| **npm** (JS/TS) | `package-lock.json` (v1–v3), `pnpm-lock.yaml` (v5–v9), `yarn.lock` (classic e berry), `bun.lock`; sem lockfile: `package.json` | AST do Babel: `import`/`require`/`import()`/re-exports, bindings realmente usados, membros acessados, `import type` |
| **Python** | `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock.toml` (PEP 751), `Pipfile.lock`, `requirements*.txt` (incluindo `-r` e o grafo `# via` do pip-compile); sem lock: `pyproject.toml` | módulo `ast` do próprio Python: aliases, atributos usados, `if TYPE_CHECKING:`, strings em settings (Django `INSTALLED_APPS`), comandos em `Procfile`/`Dockerfile` |
| **Java / Kotlin – Maven** | `mvn dependency:tree` (ou `./mvnw`); sem Maven: resolvedor próprio que lê `pom.xml` + Maven Central | imports em `.java`/`.kt`, pacotes reais do `.jar` quando ele está em `~/.m2` / cache do Gradle |
| **Java / Kotlin – Gradle** | `gradle.lockfile`; `./gradlew dependencies`; sem Gradle: `build.gradle(.kts)` + `libs.versions.toml` + BOM do Spring Boot, resolvidos via Maven Central | igual ao Maven |

Um repositório pode ter vários projetos: o Hawkeye encontra todos numa única execução, por exemplo
`frontend/` (npm), `backend/` (Maven) e `services/worker` (Python). Módulos Maven, subprojetos Gradle e
workspaces npm/uv não são contados duas vezes.

**Fontes de dados:** [OSV.dev](https://osv.dev), que agrega GitHub Advisory Database, PyPA e outras, para as
vulnerabilidades; [FIRST EPSS](https://www.first.org/epss/) para a probabilidade de exploração; e
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) para exploração ativa confirmada.

---

## 🔧 Instalação

Requisitos:

- **Node.js 20+** (obrigatório)
- **Acesso HTTPS** a `api.osv.dev` (obrigatório), `api.first.org` e `www.cisa.gov` (opcionais: sem eles o
  resultado sai sem EPSS/KEV e com um aviso). Para Java sem Maven/Gradle instalado, também `repo1.maven.org`.
- **python3** (recomendado para projetos Python; sem ele, os imports são detectados por regex, só nível 1)
- **Maven ou Gradle** (opcional, para projetos Java): com eles a árvore de dependências é exata; sem eles
  usa o resolvedor próprio, que bateu 100% com o Maven nos testes (veja [Validação](#-validação))

```bash
git clone https://github.com/lucasvsantos591-hue/hawkeye.git
cd hawkeye
npm ci
npm run build
node dist/cli/index.js --help
```

Para ter o comando `hawkeye` no PATH: `npm link` dentro da pasta (ou use `node dist/cli/index.js`).

---

## 🚀 Uso rápido

```bash
# Analisar um repositório inteiro (detecta npm, Python, Maven e Gradle)
hawkeye analyze /caminho/do/repo > resultado.json

# Relatório HTML para abrir no navegador
hawkeye analyze /caminho/do/repo -f html -o relatorio.html

# SARIF para GitHub Code Scanning / IDEs
hawkeye analyze /caminho/do/repo -f sarif -o hawkeye.sarif

# Só alguns ecossistemas
hawkeye analyze . --only python
hawkeye analyze . --only java          # = maven,gradle

# Barrar o CI se houver vulnerabilidade ALCANÇÁVEL de severidade HIGH ou maior (exit code 2)
hawkeye analyze . --fail-on high > /dev/null

# Consultar um pacote específico, sem analisar código
hawkeye scan lodash 4.17.20 -f table
hawkeye scan pyyaml 5.3 -e pypi -f table
hawkeye scan org.yaml:snakeyaml 1.30 -e maven -f table
```

O progresso vai para **stderr** e o resultado para **stdout** (ou para o arquivo de `-o`), então
`hawkeye analyze . > out.json` sempre gera JSON válido.

---

## 📖 Referência da CLI

### `hawkeye analyze <path>`

Analisa um repositório ou projeto.

| Opção | Padrão | Descrição |
|---|---|---|
| `-f, --format` | `json` | `json`, `html` ou `sarif` |
| `-o, --output` | stdout | Arquivo de saída |
| `--level` | `2` | `1` = pacote importado; `2` = bindings importados são usados; `3` = ainda não implementado (roda o 2 com aviso) |
| `--only` | todos | `npm,python,maven,gradle` ou `java` |
| `--include-dev` | `false` | Inclui devDependencies / grupos dev / escopo `test` |
| `--no-build-tool` | – | Não executa `mvn`/`gradle` (lê só os arquivos de build) |
| `--fail-on` | – | `low`, `medium`, `high`, `critical`: exit code 2 se existir finding alcançável nessa severidade ou acima |
| `--exposure <arquivo>` | – | Saída do `hawkeye expose -o`; veja [Contexto de exposição](#-contexto-de-exposição-e-remediação-com-ia) |
| `--cache <dir>` / `--no-cache` | `~/.cache/hawkeye` | Cache das respostas do OSV/EPSS/KEV/Maven Central |

Exit codes: `0` ok, `1` erro, `2` limite do `--fail-on` atingido.

> ⚠️ Rodar `mvn`/`gradle` executa os scripts de build do projeto analisado. Em repositórios de terceiros ou não
> confiáveis, use `--no-build-tool`.

### `hawkeye scan <package> <version>`

Lista as vulnerabilidades conhecidas de uma versão, sem reachability. `-e/--ecosystem npm|pypi|maven` (padrão
`npm`) e `-f json|table`. No Maven o nome é `groupId:artifactId`. Cada linha traz `epss_status` e `kev_status`
(veja [Status de EPSS e KEV](#status-de-epss-e-kev)).

### `hawkeye report <input.json>`

Gera relatórios a partir de um JSON do `analyze`.

| Opção | Descrição |
|---|---|
| `-f, --format` | `html` (padrão), `markdown`, `json`, `docx`, `sarif` |
| `-o, --output` | Arquivo de saída (obrigatório para `docx`) |
| `--enrichment` | Reconsulta EPSS/KEV e grava os status por CVE (útil para JSONs antigos) |
| `--exposure <arquivo>` | Saída do `hawkeye expose -o`, anexada ao resultado (igual ao `analyze`) |
| `--ai-provider` | `claude`, `openai`, `gemini`, `custom` ou `none` (padrão), para sugestões de remediação por IA |
| `--ai-token`, `--ai-model`, `--ai-base-url` | Credencial, modelo e endpoint (`custom` = qualquer API compatível com OpenAI) |

### `hawkeye batch <diretório>`

Analisa cada subdiretório que contenha um projeto suportado. `--concurrency` (padrão 2), `--level`,
`--include-dev`, `-o <dir>` grava um JSON por projeto. O resumo vai para stderr e o JSON consolidado para stdout.

### `hawkeye expose <hostname>`

Heurística de exposição à internet para um hostname: resolve o DNS (resolvedor do sistema), tenta um handshake TLS e
requisições HTTP direto no host. `-o` grava o resultado em JSON, que o `analyze` e o `report` recebem com
`--exposure` (veja [Contexto de exposição](#-contexto-de-exposição-e-remediação-com-ia)). Só fala com o host
informado e com o seu DNS; nenhum serviço de terceiros é consultado.

### Servidor HTTP

`node dist/cli/server.js`, veja [API HTTP e Docker](#-api-http-e-docker).

---

## ⚙️ Como funciona

```
 repositório
     │
     ├─ 1. Descoberta ─────────── package.json / *.lock / requirements*.txt / pyproject.toml / pom.xml / build.gradle
     │                            (até 4 níveis; ignora node_modules, target, build, venv, tests, examples…)
     │
     ├─ 2. Inventário ────────── versão instalada de cada pacote, direto × transitivo,
     │                            quais dependências diretas puxam cada transitiva (e a que distância), prod × dev
     │
     ├─ 3. Vulnerabilidades ──── OSV.dev querybatch por (ecossistema, nome, versão)
     │                            → advisories (duplicatas GHSA/PYSEC/CVE unificadas por alias),
     │                              severidade, faixas afetadas, versão corrigida
     │
     ├─ 4. Reachability ──────── índice de uso do código, construído só para projetos com pacotes vulneráveis
     │
     ├─ 5. Enriquecimento ────── EPSS (probabilidade de exploração em 30 dias) + CISA KEV,
     │                            pelo CVE e pelos aliases; todo finding recebe um status de cada
     │
     └─ 6. Priorização ───────── alcançável → KEV → severidade → confiança → EPSS
```

### Regras de reachability

**npm e Python:**

| Situação | Resultado | Confiança |
|---|---|---|
| Importado e usado em código de produção | **alcançável** (nível 2), com membros e `arquivo:linha` | 80 |
| Não usado diretamente, mas outra dependência usada depende dele | **alcançável**, herdado | ≤ 60 |
| Transitiva de uma dependência direta que é usada | **alcançável** | ≤ 60 |
| Python: servidor/driver iniciado por comando (`Procfile`, `Dockerfile`, `*.sh`) ou carregado sem import (gunicorn, uvicorn, psycopg2, python-multipart…) | **alcançável** | 50 |
| Não dá para saber se é direta ou transitiva (ex.: `pip freeze`) e não é importada | **alcançável** (conservador) | 30 |
| Importado mas nenhum nome importado é usado | não alcançável | 70 |
| Declarado e nunca importado | não alcançável | 60–70 |
| Só importado em testes | não alcançável | 80 |
| Só `import type` (TS) / só em `if TYPE_CHECKING:` (Python) | não alcançável | 90 |
| Transitiva puxada só por dependências que não são usadas | não alcançável | 60 |

**Qual direta explica uma transitiva:** quando várias dependências diretas usadas puxam o mesmo pacote, vale a
de maior confiança; no empate, a **mais próxima no grafo** (o `fastapi` depende direto do `starlette`, então ganha
de uma biblioteca interna que só chega ao `starlette` através do `fastapi`) e depois a usada em mais arquivos. As
demais aparecem no `reason` (*"Also pulled in by …"*), para a remediação não depender de uma só. Dependências
de teste nunca aparecem em `introduced_via` de um pacote de produção.

**Java (Maven/Gradle):** bibliotecas Java são muito carregadas sem import (backends de log como log4j-core,
drivers JDBC, auto-configuração do Spring). Por isso, **nenhuma dependência de produção é marcada como não
alcançável** só por falta de import:

| Situação | Resultado | Confiança |
|---|---|---|
| Importada no código (classes listadas) | **alcançável** | 80 |
| Transitiva de uma dependência usada | **alcançável** | 60 |
| Sem imports | **alcançável** (carregamento em runtime) | 40 |
| Escopo `test` (só com `--include-dev`) | não alcançável | 90 |

No Java, a reachability serve para **priorizar** (confiança e evidência), não para descartar.

### Remediação sugerida

| Projeto | Dependência direta | Transitiva |
|---|---|---|
| npm | `npm install pkg@^X` | `npm pkg set overrides.pkg=^X` |
| Python | `uv add` / `poetry add` / `pdm add` / `pipenv install` / editar `requirements.txt` | constraint (`constraint-dependencies`, arquivo de constraints) |
| Maven | `mvn versions:use-dep-version …` | fixar em `<dependencyManagement>` |
| Gradle | trocar a versão no build/catálogo | `dependencies { constraints { … } }` |

`type` vem como `MAJOR` quando a correção exige subir a versão major (provável breaking change). Pacotes
maliciosos (advisories `MAL-*`) viram CRITICAL com instrução de remoção.

### Score de risco

`overall_risk_score` (0–100) é o pior finding alcançável: base por severidade (CRITICAL 90, HIGH 70,
MEDIUM 45, LOW 20), +10 se estiver no CISA KEV e até +10 pelo EPSS.

---

## 📊 Entendendo o resultado

Trecho real de `hawkeye analyze` (JSON):

```json
{
  "vulnerability": {
    "cve_id": "CVE-2021-23337",
    "advisory_id": "GHSA-35jh-r3h4-6jhm",
    "summary": "Command Injection in lodash",
    "advisory_url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
    "ecosystem": "npm",
    "project": ".",
    "manifest": "package-lock.json",
    "package": "lodash",
    "current_version": "4.17.10",
    "affected_versions": ["<4.17.21"],
    "fixed_version": "4.17.21",
    "severity": "HIGH",
    "dependency_type": "direct",
    "introduced_via": [],
    "is_dev": false,
    "epss_score": 21.33,
    "epss_percentile": 97.53,
    "epss_status": "scored",
    "is_exploited_in_wild": false,
    "kev_status": "not_listed"
  },
  "is_reachable": true,
  "reachability_level": 2,
  "confidence": 80,
  "reason": "Used in 1 file(s). Uses: map, template.",
  "evidence": {
    "files": ["src/index.js"],
    "members": ["map", "template"],
    "sites": ["src/index.js:16", "src/index.js:27"]
  },
  "remediation": {
    "type": "MINOR",
    "description": "Upgrade lodash from 4.17.10 to 4.17.21 or later.",
    "action": "npm install lodash@^4.17.21"
  }
}
```

Campos principais:

| Campo | Significado |
|---|---|
| `is_reachable`, `confidence` | Decisão e o quanto confiar nela (veja as tabelas acima) |
| `reason` | Por que a decisão foi tomada, em texto |
| `evidence.sites` / `members` | Onde e o que o código usa do pacote |
| `dependency_type`, `introduced_via` | Direta ou transitiva e quais dependências diretas a puxam |
| `epss_score`, `epss_status` | Probabilidade (%) de exploração nos próximos 30 dias; `epss_percentile` compara com todos os CVEs |
| `is_exploited_in_wild`, `kev_status` | Está no catálogo CISA KEV (exploração ativa confirmada); `kev_date_added` quando listada |
| `project`, `manifest` | Subprojeto e arquivo de onde a versão foi lida |
| `scan.projects`, `scan.warnings` | O que foi analisado e **tudo que pode ter reduzido a precisão** (lockfile ausente, falha do Maven, arquivos não parseados, EPSS fora do ar…) |
| `scan.threat_intel` | Qual catálogo KEV foi consultado (versão, data, nº de CVEs) e se EPSS/KEV responderam |
| `context.exposure` | Saída do `hawkeye expose`, quando passada com `--exposure` |
| `project_path` | Caminho relativo ao diretório atual; omitido se a análise rodou fora dele, para não expor o caminho local de quem rodou |

Resumo do topo: `total_vulnerabilities`, `reachable_vulnerabilities`, `summary.critical_reachable`, `high_…`,
`medium_…`, `low_reachable` e `summary.false_positives_filtered` (vulnerabilidades presentes, mas avaliadas como
não alcançáveis).

### Status de EPSS e KEV

Todo finding diz o resultado das duas consultas, inclusive quando é negativo, para ficar claro que a checagem foi
feita em cada CVE:

| Status | EPSS (`epss_status`) | CISA KEV (`kev_status`) |
|---|---|---|
| Consultado, com resultado | `scored`: score e percentil | `listed`: exploração ativa confirmada, com a data de inclusão |
| Consultado, sem resultado | `not_scored`: ainda sem score (em geral, CVE publicada há poucos dias) | `not_listed`: sem exploração conhecida |
| Fonte fora do ar | `not_checked` | `not_checked` (nunca vira "não listada") |
| Advisory sem CVE | `no_cve`: EPSS só pontua CVEs | `no_cve`: o KEV só lista CVEs |

A consulta usa o CVE principal e todos os aliases do advisory. JSONs gerados antes desses campos continuam
funcionando: `hawkeye report` deduz o status, e `--enrichment` reconsulta as fontes.

**Como revisar:** comece pelos alcançáveis com KEV ou severidade alta. Nos "não alcançáveis", leia o
`reason`: *"declared but never imported"* pode ser um plugin carregado por configuração.

**HTML:** totais por severidade (CRITICAL, HIGH, MEDIUM e LOW) e qual catálogo KEV/EPSS foi consultado; depois um
card por finding, com severidade, versão corrigida, EPSS, KEV (sempre com o status), tags (ecossistema,
subprojeto, direta/transitiva), onde é usado e a remediação. Todo texto é escapado e a página tem CSP restritiva.
Markdown e DOCX trazem os mesmos status de EPSS e KEV. O DOCX (`hawkeye report -f docx`) tem uma página por
finding alcançável, montada só com dados do resultado: advisory, motivo da reachability, onde o código usa o
pacote e o comando de correção.

**SARIF 2.1.0:** cada resultado aponta para o primeiro `arquivo:linha` onde o pacote é usado (ou para o
lockfile/manifest), com `security-severity` para o GitHub Code Scanning.

---

## 🔁 Integração com CI/CD

### GitHub Actions (SARIF + gate)

```yaml
name: Hawkeye
on: [push, pull_request]

jobs:
  hawkeye:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      # Opcional para Java: actions/setup-java para usar mvn/gradle (árvore exata)
      - name: Build Hawkeye
        run: |
          git clone --depth 1 https://github.com/lucasvsantos591-hue/hawkeye.git /tmp/hawkeye
          cd /tmp/hawkeye && npm ci && npm run build
      - name: Analyze
        run: node /tmp/hawkeye/dist/cli/index.js analyze . -f sarif -o hawkeye.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: hawkeye.sarif
      - name: Gate on reachable HIGH+
        run: node /tmp/hawkeye/dist/cli/index.js analyze . --fail-on high > /dev/null
```

Os exemplos de GitLab CI e Azure Pipelines estão no [DEPLOYMENT.md](./DEPLOYMENT.md).

---

## 🌐 API HTTP e Docker

```bash
docker build -t hawkeye .
docker run -p 3000:3000 \
  -e HAWKEYE_API_TOKEN=troque-isto \
  -v /srv/repos:/workspace:ro \
  hawkeye

curl localhost:3000/api/health
curl -X POST localhost:3000/api/analyze \
  -H "Authorization: Bearer troque-isto" \
  -d '{"projectPath": "meu-repo", "format": "json", "includeDev": false}'
```

| Endpoint | Descrição |
|---|---|
| `GET /api/health` | Status, versão, uptime, análises em andamento (sem autenticação) |
| `POST /api/analyze` | `{ projectPath, level?, format?: "json"\|"html"\|"sarif", includeDev? }` |
| `POST /api/report` | `{ analysisResult, format?: "html"\|"sarif"\|"json", projectPath? }` |

Segurança:

- Exige `HAWKEYE_API_TOKEN` (Bearer) para escutar fora de localhost; sem token o servidor se recusa a subir.
- `projectPath` é resolvido dentro de `HAWKEYE_ALLOWED_ROOT`, com symlinks resolvidos; qualquer caminho fora dele recebe 403.
- Corpo limitado a 5 MB; no máximo `HAWKEYE_MAX_CONCURRENCY` análises simultâneas (429 acima disso); CORS só se `HAWKEYE_CORS_ORIGIN` for definido.
- A API **não executa mvn/gradle** (isso rodaria scripts do projeto) a menos que `HAWKEYE_ALLOW_BUILD_TOOLS=1`.
- A imagem roda como usuário `node`, inclui `python3` e não tem TLS: coloque um proxy reverso na frente.

Mais detalhes em [DEPLOYMENT.md](./DEPLOYMENT.md).

---

## 🧭 Contexto de exposição e remediação com IA

**Contexto (`.hawkeye.yaml` / `.hawkeye.json` na raiz do projeto):** informa a exposição da aplicação. O
relatório HTML ajusta o score (×1.5 `internet-facing`, ×0.8 `internal-only`, ×0.4 `isolated`) e mostra o motivo.

```yaml
application_name: payments-api
environment: production
exposure: internet-facing   # internet-facing | internal-only | isolated | unknown
compliance:
  pci_dss: true
custom_tags:
  team: payments
```

O mesmo exemplo, comentado, está em [`examples/hawkeye.example.yaml`](./examples/hawkeye.example.yaml). O rescoring é
heurístico e **não altera** `is_reachable`.

**Exposição detectada (`hawkeye expose`):** em vez de declarar, dá para medir:

```bash
hawkeye expose api.minha-empresa.com -o exposure.json
hawkeye analyze . --exposure exposure.json -f html -o relatorio.html
```

O resultado vai para `context.exposure` no JSON, o HTML mostra de onde veio a exposição e o DOCX ganha uma seção com
DNS, certificado e endpoints. A detecção **só aumenta** o risco: host acessível pela internet vira `internet-facing`
(mesmo que o `.hawkeye.yaml` diga outra coisa, com um aviso); host que não respondeu não prova isolamento, então vale
o que estiver declarado, ou `unknown`.

**IA (opcional):** `hawkeye report resultado.json --ai-provider claude` gera sugestões de remediação por
finding. Tokens: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` ou `--ai-token`; o modelo pode ser
trocado com `--ai-model`. O provedor recebe CVE, pacote, versões, severidade e o caminho de dependências, nunca
código-fonte (o que sai da máquina está no [SECURITY.md](./SECURITY.md)). No relatório as sugestões aparecem
marcadas como geradas por IA: **revise antes de executar qualquer comando**.

---

## 🔩 Configuração (variáveis de ambiente)

| Variável | Padrão | Uso |
|---|---|---|
| `HAWKEYE_CACHE_DIR` | `~/.cache/hawkeye` | Cache de advisories, EPSS, KEV e POMs |
| `HAWKEYE_OSV_URL` | `https://api.osv.dev/v1` | Espelho do OSV |
| `HAWKEYE_EPSS_URL` | `https://api.first.org/data/v1/epss` | Espelho do EPSS |
| `HAWKEYE_KEV_URL` | feed oficial da CISA | Espelho do KEV |
| `HAWKEYE_MAVEN_REPO` | `https://repo1.maven.org/maven2` | Repositório Maven (ex.: Nexus/Artifactory interno) |
| `HAWKEYE_API_TOKEN` | – | Token da API |
| `HAWKEYE_HOST` / `HAWKEYE_PORT` | `127.0.0.1` / `3000` | Endereço da API (`0.0.0.0` no Docker) |
| `HAWKEYE_ALLOWED_ROOT` | diretório atual (`/workspace` no Docker) | Raiz permitida para a API |
| `HAWKEYE_MAX_CONCURRENCY` | `2` | Análises simultâneas na API |
| `HAWKEYE_CORS_ORIGIN` | – | Origem permitida para browsers |
| `HAWKEYE_ALLOW_BUILD_TOOLS` | – | `1` permite a API rodar mvn/gradle |

TTLs do cache: consultas ao OSV 6 h, advisories 7 dias, EPSS/KEV 24 h, POMs 30 dias.

---

## ✅ Validação

Testado em 2026-09-29 e 2026-10-05 contra projetos reais:

| Projeto | Ecossistema | Verificação | Resultado |
|---|---|---|---|
| App de exemplo (express/lodash/axios) | npm | pacotes vulneráveis × `npm audit` | idênticos; mesmo resultado com lock npm, pnpm, yarn v1 e yarn berry |
| nestjs/nest (2.047 arquivos) | npm | desempenho | 5 s |
| excalidraw (monorepo yarn) | npm | desempenho, workspaces | 8 s |
| fastapi/full-stack-fastapi-template | Python (uv workspace) + npm (bun) | multi-projeto | backend e frontend detectados, sem duplicar |
| saleor (2.861 arquivos) | Python (uv.lock, Django) | desempenho | 9 s |
| python-poetry/poetry, pypa/pipenv, pypi/warehouse | poetry.lock, Pipfile.lock, pylock.toml, pip-compile | parsing | todos lidos |
| spring-projects/spring-petclinic | Maven | resolvedor × `mvn dependency:tree` | **106/106 pacotes idênticos** |
| WebGoat | Maven | resolvedor × `mvn dependency:tree` | **191/191 pacotes idênticos**; xstream 1.4.5 detectado e usado |
| spring-petclinic (build.gradle) | Gradle | resolvedor × `gradlew dependencies` | todas as bibliotecas de runtime idênticas |
| fastapi/full-stack-fastapi-template (jan/2025) | Python (uv.lock) | versão anterior × atual do Hawkeye | mesmos 53 findings; a direta creditada passou a ser a mais próxima (ex.: `urllib3` via `sentry-sdk`, não via `emails` → `requests`) e as 6 LOW entram no resumo |
| Serviço FastAPI interno (58 pacotes, 636 arquivos) | Python (uv.lock) | EPSS/KEV × FIRST e catálogo da CISA | 21/21 idênticos: 1 listada no KEV, 19 não listadas, 1 advisory sem CVE |

Cerca de 90 testes unitários rodam offline (lockfiles reais como fixtures, APIs simuladas).

---

## ⚠️ Limitações conhecidas

- **Não identifica a função vulnerável.** Os advisories raramente dizem qual função está afetada. O
  Hawkeye mostra *que* o pacote é usado e *o que* é usado dele; cruzar com o advisory é trabalho humano.
- **Nível 3 (data-flow/taint) não existe.** `--level 3` roda o nível 2.
- **Carregamento indireto** (plugins configurados por string, entry points, reflexão) pode aparecer como
  "declared but never imported" em npm/Python. No Java isso é tratado como alcançável de propósito.
- **Transitivas herdam a reachability da dependência direta**: não se verifica se o caminho vulnerável *dentro*
  da biblioteca é exercitado.
- **Sem lockfile / `pip freeze`:** precisão menor (ver `scan.warnings`). Commite o lockfile.
- **Resolvedor Java sem Maven/Gradle:** não aplica profiles, plugins que mudam dependências, version ranges
  nem repositórios privados, exceto via `HAWKEYE_MAVEN_REPO`. Com `mvn`/`gradle` disponível, a árvore é exata.
- **Gradle:** só a configuração `runtimeClasspath` (e `testRuntimeClasspath` com `--include-dev`); os plugins
  Android/KMP não foram testados.
- **Ecossistemas não suportados:** Go, Rust, Ruby, PHP, .NET, containers/SO.
- **Requer rede** para OSV (não há modo offline).

---

## 🛠️ Desenvolvimento

```bash
npm ci
npm run build        # tsc → dist/
npm test             # vitest (offline)
npm run lint         # eslint
npx tsc --noEmit     # typecheck
```

Estrutura:

```
src/
├── cli/
│   ├── index.ts                  # yargs: analyze, scan, report, batch, expose
│   ├── server.ts                 # API HTTP
│   └── commands/                 # um arquivo por comando
├── core/
│   ├── analysis_engine.ts        # orquestra: descoberta → inventário → OSV → reachability → EPSS/KEV
│   ├── project_discovery.ts      # encontra projetos npm/Python/Maven/Gradle no repositório
│   ├── dependency_inventory.ts   # lockfiles npm (npm, pnpm, yarn, bun)
│   ├── ecosystems/
│   │   ├── python_inventory.ts   # uv/poetry/pdm/pylock/Pipfile/requirements/pyproject
│   │   ├── java_inventory.ts     # mvn/gradle tree, lockfiles, build.gradle, catálogo de versões
│   │   └── maven_resolver.ts     # resolvedor de POM (parent, BOM, nearest-wins, exclusões)
│   ├── import_index.ts           # uso em JS/TS (Babel)
│   ├── python_index.ts           # uso em Python (ast via python3)
│   ├── java_index.ts             # uso em Java/Kotlin (imports + conteúdo do jar)
│   ├── threat_intel.ts           # EPSS + CISA KEV
│   ├── versions.ts               # comparação de versões semver/PEP 440/Maven
│   ├── inventory_types.ts, cache_manager.ts, http.ts, batch_processor.ts, risk_rescorer.ts
├── adapters/
│   ├── vulnerability_sources/osv_source.ts
│   ├── report/                   # html, sarif, docx; threat_labels.ts = status de EPSS/KEV
│   ├── ai_providers/             # claude, openai, gemini, custom
│   └── context/                  # .hawkeye.yaml e saída do expose (contexto de exposição)
└── types/analysis-result.ts      # schema do resultado
tests/unit/                        # testes offline; fixtures em tests/fixtures
```

Contribuições: veja [CONTRIBUTING.md](./CONTRIBUTING.md). Para reportar vulnerabilidades no próprio Hawkeye:
[SECURITY.md](./SECURITY.md).

---

## 🗺️ Roadmap

- Símbolos vulneráveis por advisory (quando o OSV trouxer) para reachability no nível da função
- Call graph entre arquivos (nível 2 real, de ponto de entrada até a função)
- Go e .NET
- Modo offline com base OSV local
- Cache compartilhado para a API em múltiplas instâncias

---

## 📄 Licença

[MIT](./LICENSE)
