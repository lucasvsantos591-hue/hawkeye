# 🎯 🧪 Hawkeye V1 Testing Guide for Corporate Teams

**Objetivo**: Testar Hawkeye V1 em cenários reais e coletar feedback para V2.

**Lema**: Um tiro, um alvo. Ajude-nos a acertar na mosca! 🎯

**Duração estimada**: 30-60 minutos por tester.

---

## ✅ Setup Inicial

### Pré-requisitos
```bash
# Node.js 18+
node --version

# Clone e build
git clone https://github.com/lucasvsantos591-hue/hawkeye.git
cd hawkeye
npm install
npm run build

# Verify CLI works
node dist/cli/index.js --help
```

### API Keys (Escolha uma ou mais)
```bash
# Option 1: Claude (Anthropic)
export ANTHROPIC_API_KEY="sk-ant-..."

# Option 2: OpenAI
export OPENAI_API_KEY="sk-..."

# Option 3: Google Gemini
export GEMINI_API_KEY="AIzaSy..."

# Option 4: Self-hosted (Ollama/Groq - nenhuma chave necessária)
# Será testado com --ai-base-url http://localhost:8000/v1
```

---

## 🧬 Test Cases

### Test 1: Básico - Análise Determinística (sem IA)

**Objetivo**: Validar que `vra analyze` funciona offline e é reprodutível.

**Passos**:
```bash
# 1. Rodar análise de um projeto exemplo
node dist/cli/index.js analyze tests/fixtures/analysis-results/sample-basic.json \
  --output my-analysis.json

# 2. Rodar novamente
node dist/cli/index.js analyze tests/fixtures/analysis-results/sample-basic.json \
  --output my-analysis-2.json

# 3. Comparar: os dois arquivos devem ser IDÊNTICOS
diff my-analysis.json my-analysis-2.json
# Esperado: sem output (arquivos iguais)
```

**Sucesso**: ✅ Arquivo JSON gerado e reprodutível
**Questões a responder**:
- [ ] A análise completou sem erros?
- [ ] O JSON é bem estruturado?
- [ ] Os resultados são sempre iguais?

---

### Test 2: Relatório HTML (sem IA)

**Objetivo**: Validar rendering do relatório HTML.

**Passos**:
```bash
# 1. Gerar relatório HTML (análise anterior)
node dist/cli/index.js report my-analysis.json \
  --format html \
  --ai-provider none \
  --output report-no-ai.html

# 2. Abrir em browser
# macOS:
open report-no-ai.html

# Linux:
xdg-open report-no-ai.html

# Windows:
start report-no-ai.html
```

**Sucesso**: ✅ HTML carrega no browser, mostra vulnerabilidades, é legível
**Questões a responder**:
- [ ] O HTML é responsivo (mobile-friendly)?
- [ ] Todos os campos aparecem corretamente?
- [ ] Cores e layout fazem sentido?
- [ ] Elementos MAJOR/MINOR/OPTIONAL estão claros?

---

### Test 3: Relatório Markdown

**Objetivo**: Validar que Markdown é renderizável.

**Passos**:
```bash
# 1. Gerar Markdown
node dist/cli/index.js report my-analysis.json \
  --format markdown \
  --ai-provider none

# 2. Copiar para um arquivo
node dist/cli/index.js report my-analysis.json \
  --format markdown \
  --ai-provider none \
  --output report.md

# 3. Abrir em editor ou GitHub (se subir para repo)
cat report.md
```

**Sucesso**: ✅ Markdown é bem formatado, headers funcionam, lists aparecem
**Questões a responder**:
- [ ] Markdown syntax está correto?
- [ ] Tamanho do arquivo é razoável?
- [ ] Seria útil para documentação interna?

---

### Test 4: Relatório JSON (para piping/integração)

**Objetivo**: Validar que JSON pode ser parseado e processado.

**Passos**:
```bash
# 1. Gerar JSON
node dist/cli/index.js report my-analysis.json \
  --format json \
  --ai-provider none \
  --output report.json

# 2. Validar JSON válido
python3 -c "import json; json.load(open('report.json')); print('✅ JSON válido')"

# 3. Processar com ferramentas
# Exemplo: contar CVEs reachable
cat report.json | grep '"is_reachable": true' | wc -l
```

**Sucesso**: ✅ JSON é válido e pode ser processado
**Questões a responder**:
- [ ] JSON é válido?
- [ ] Esquema é estável (não muda)?
- [ ] Fácil de parsear em Python/Go/Java?

---

### Test 5: AI Enhancement - Claude

**Objetivo**: Validar integração com Claude (se tiver API key).

**Passos**:
```bash
# 1. Garantir ANTHROPIC_API_KEY está set
echo $ANTHROPIC_API_KEY  # deve ter valor

# 2. Gerar relatório COM Claude
node dist/cli/index.js report my-analysis.json \
  --format html \
  --ai-provider claude \
  --output report-claude.html

# 3. Abrir em browser e comparar com versão sem IA
# Procurar por: sugestões de remediação, "effort_estimate", "changes_needed"
```

**Sucesso**: ✅ Claude foi chamado, sugestões aparecem no HTML
**Questões a responder**:
- [ ] Claude foi realmente chamado (ou foi offline)?
- [ ] Sugestões de remediação fazem sentido?
- [ ] Effort estimates são realistas?
- [ ] Tempo de resposta aceitável (< 30s)?
- [ ] Custo estimado: é aceitável?

---

### Test 6: AI Enhancement - OpenAI

**Objetivo**: Validar integração com OpenAI (se tiver API key).

**Passos**:
```bash
# 1. Set OPENAI_API_KEY
echo $OPENAI_API_KEY  # deve ter valor

# 2. Gerar com GPT
node dist/cli/index.js report my-analysis.json \
  --format markdown \
  --ai-provider openai \
  --output report-gpt.md

# 3. Comparar qualidade com Claude
# Claude vs GPT: qual tem melhores sugestões?
```

**Sucesso**: ✅ OpenAI funcionou, sugestões aparecem
**Questões a responder**:
- [ ] OpenAI foi chamado?
- [ ] Resposta é diferente de Claude (esperado)?
- [ ] Qualidade é comparable?
- [ ] Custo vs Claude?

---

### Test 7: AI Enhancement - Gemini

**Objetivo**: Validar integração com Gemini.

**Passos**:
```bash
# 1. Set GEMINI_API_KEY ou GOOGLE_API_KEY
echo $GEMINI_API_KEY

# 2. Gerar com Gemini
node dist/cli/index.js report my-analysis.json \
  --format html \
  --ai-provider gemini \
  --output report-gemini.html
```

**Sucesso**: ✅ Gemini funcionou
**Questões a responder**:
- [ ] Gemini foi chamado?
- [ ] Latência: mais rápido/lento que Claude?
- [ ] Qualidade das sugestões?
- [ ] Preço competitivo?

---

### Test 8: Custom/Self-hosted Endpoint

**Objetivo**: Validar que funciona com endpoint custom (Ollama, Groq, etc).

**Passos** (requer servidor rodando):
```bash
# 1. Iniciar Ollama (ou outro servidor compatible com OpenAI API)
ollama serve

# Em outro terminal:

# 2. Puxar modelo (first time only)
ollama pull llama2

# 3. Rodar VRA com custom endpoint
node dist/cli/index.js report my-analysis.json \
  --format html \
  --ai-provider custom \
  --ai-base-url http://localhost:11434/v1 \
  --ai-token ignored \
  --output report-local.html
```

**Sucesso**: ✅ Custom endpoint funcionou, relatório gerado
**Questões a responder**:
- [ ] Custom endpoint foi aceito?
- [ ] Sem custo de API (local)?
- [ ] Performance aceitável?
- [ ] Privacidade: dados não saem da rede?

---

### Test 9: Error Handling - AI API Fails

**Objetivo**: Validar que VRA é resiliente se IA cair.

**Passos**:
```bash
# 1. Tentar com token inválido
node dist/cli/index.js report my-analysis.json \
  --format html \
  --ai-provider claude \
  --ai-token invalid-key-12345 \
  --output report-error.html

# Esperado: ⚠️ Warning, mas HTML é gerado mesmo assim
```

**Sucesso**: ✅ Report foi gerado mesmo com erro de API
**Questões a responder**:
- [ ] Mensagem de erro é clara?
- [ ] HTML base é gerado sem IA?
- [ ] Não cravou/not crash?

---

### Test 10: Scalability - Projeto Grande

**Objetivo**: Testar com um projeto real/grande.

**Passos**:
```bash
# 1. Clone um projeto famoso (ou use seu próprio)
git clone https://github.com/expressjs/express /tmp/express
# ou
git clone https://github.com/django/django /tmp/django

# 2. Rodar análise (pode demorar)
time node dist/cli/index.js analyze /tmp/express --level 2 --output big-analysis.json

# 3. Rodar relatório
time node dist/cli/index.js report big-analysis.json \
  --format html \
  --ai-provider none \
  --output big-report.html
```

**Sucesso**: ✅ Análise completou sem memory issues
**Questões a responder**:
- [ ] Tempo total aceitável (< 5 min)?
- [ ] Memória use explodiu?
- [ ] CPU ficou razoável?
- [ ] Resultado é correto?

---

## 📋 Feedback Form

Após completar os testes, por favor preencha este formulário:

```markdown
## VRA V1 Feedback Report

**Tester**: [seu nome]
**Date**: [data]
**Company**: [empresa]
**Project tested**: [qual projeto/codebase]

### Testes Completados
- [ ] Test 1: Deterministic analysis
- [ ] Test 2: HTML report
- [ ] Test 3: Markdown report
- [ ] Test 4: JSON report
- [ ] Test 5: Claude AI
- [ ] Test 6: OpenAI AI
- [ ] Test 7: Gemini AI
- [ ] Test 8: Custom endpoint
- [ ] Test 9: Error handling
- [ ] Test 10: Large project

### Usabilidade (1-5, 5=excelente)
- Comandos intuitivos? **___/5**
- Documentação clara? **___/5**
- Erro messages úteis? **___/5**
- Overall UX: **___/5**

### Accuracy (1-5, 5=perfeito)
- Detecta real vulnerabilities? **___/5**
- Falsos positivos aceitáveis? **___/5**
- Reachability analysis é confiável? **___/5**

### Performance (1-5, 5=muito rápido)
- Análise rápida? **___/5**
- Relatório rápido? **___/5**
- AI integration snappy? **___/5**

### Security (1-5, 5=muito seguro)
- API keys são seguras (não logadas)? **___/5**
- Dados corporativos ficam privados? **___/5**
- Self-hosted option (Ollama) works? **___/5**

### Integração no Workflow (1-5, 5=perfeito encaixe)
- Encaixa em CI/CD? **___/5**
- Útil para code review? **___/5**
- Pronto para production? **___/5**

### Top 3 Melhorias Desejadas (V2)
1. _________________________________
2. _________________________________
3. _________________________________

### Comentários Adicionais
_________________________________
_________________________________

### Would you recommend VRA?
- [ ] Yes, prod-ready now
- [ ] Yes, with some fixes
- [ ] Maybe, needs work
- [ ] No, not ready
```

---

## 📧 Como Enviar Feedback

1. **GitHub Issues**: https://github.com/lucasvsantos591-hue/vra-project/issues
2. **Email**: [compartilhe com Lucas]
3. **Slack/Teams**: [compartilhe com o time]

---

## 🆘 Troubleshooting

### "Node not found"
```bash
node --version  # deve ser 18+
# Se não, install: https://nodejs.org/
```

### "API key invalid"
```bash
# Check:
echo $ANTHROPIC_API_KEY  # deve ter valor
# Se vazio, set:
export ANTHROPIC_API_KEY="sk-ant-..."
```

### "Cannot find module"
```bash
# Rebuild:
npm run build
```

### "HTML not rendering"
- Verificar se arquivo foi criado: `ls -la report.html`
- Tentar em navegador diferente
- Check console for JS errors

---

## 🎯 Success Criteria

VRA V1 é considerado **ready** se:
- ✅ Todos os 10 testes passam
- ✅ Nenhum crash/segfault
- ✅ AI integration funciona
- ✅ Relatórios são legíveis
- ✅ Time diz "essa ferramenta é útil"

---

## 📚 Referências

- [README.md](README.md) - Documentação principal
- [V2_ROADMAP.md](V2_ROADMAP.md) - Roadmap para próximas features
- [GitHub Issues](https://github.com/lucasvsantos591-hue/vra-project/issues) - Report bugs aqui

---

**Obrigado por testar VRA!** 🙏

Seu feedback é crucial para fazer isso melhor. Vamos para V2! 🚀
