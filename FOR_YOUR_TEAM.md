# 🎯 Hawkeye: Convite para Testar em Produção 🚀

Olá time! 👋

Desenvolvemos **Hawkeye** — uma ferramenta que diz se uma vulnerabilidade é **realmente explorável** no seu código, não apenas "versão X tem CVE".

**Lema**: Um tiro, um alvo. Sem desperdício de alertas falsos.

## ⚡ Quick Start

### O que é Hawkeye?

Ferramentas tradicionais (Snyk, Sonatype, etc):
```
❌ "Você tem lodash@4.15.0 com CVE-YYYY"
❌ Resultado: Cria alerta genérico, mas seu código não usa função vulnerável
❌ Outcome: 80% falsos positivos que você ignora
```

**Hawkeye** (um tiro, um alvo):
```
✅ "Você importa lodash, mas apenas usa _.map()"
✅ "A vulnerabilidade está em _.template()"
✅ "Conclusão: NÃO ALCANÇÁVEL no seu código"
✅ Outcome: Foco real, menos ruído
```

### Instalação (2 minutos)

```bash
git clone https://github.com/lucasvsantos591-hue/hawkeye.git
cd hawkeye
npm install
npm run build
```

### Uso Básico (3 exemplos)

```bash
# 1. Análise (gera JSON com vulnerabilidades)
node dist/cli/index.js analyze ./seu-projeto --level 2 --output analysis.json

# 2. Relatório sem IA (rápido, offline)
node dist/cli/index.js report analysis.json --format html --ai-provider none --output report.html
open report.html

# 3. Relatório com Claude (sugestões automáticas de fix)
# (requer ANTHROPIC_API_KEY)
node dist/cli/index.js report analysis.json \
  --format html \
  --ai-provider claude \
  --output report-with-ai.html
```

## 🎯 O que Queremos Testar

Pedimos que vocês testem em **cenário corporativo real** e respondam:

### ✅ 10 Testes Práticos (30 min)
- Veja [TESTING_GUIDE.md](TESTING_GUIDE.md) para passo-a-passo completo

**Resumo**:
1. Análise determinística (sempre igual?)
2. Relatório HTML (bonito, legível?)
3. Relatório Markdown (pronto para docs?)
4. Suporte JSON (fácil integrar?)
5-7. AI providers (Claude vs OpenAI vs Gemini?)
8. Endpoint custom (Ollama, Groq, self-hosted funciona?)
9. Resiliência (cai a IA, ainda funciona?)
10. Projetos grandes (escalável?)

### 📋 Feedback Esperado

Após testar, responda:

**1. Acurácia**:
- [ ] Detecta CVEs reais do seu projeto?
- [ ] Reachability analysis é confiável?
- [ ] Falsos positivos aceitáveis? (quantos?)

**2. Usabilidade**:
- [ ] Comandos são intuitivos?
- [ ] Documentação clara?
- [ ] Mensagens de erro ajudam?

**3. Performance**:
- [ ] Análise rápida? (< 5 min para projeto grande?)
- [ ] Relatorio gerado rápido?
- [ ] Integração com IA aceitável?

**4. Integração**:
- [ ] Encaixa no seu workflow?
- [ ] Possível usar em CI/CD?
- [ ] Pronto para produção agora?

**5. Top 3 Melhorias Desejadas**:
- Escreva 3 features que VOCÊS querem para V2

---

## 🔐 Segurança & Privacy

**Importante para empresas**:
- ✅ Hawkeye é **open-source** — code review possível
- ✅ Análise local — repositório fica no seu computador
- ✅ IA é **agnóstica** — vocês escolhem qual usar
  - Claude (Anthropic)
  - OpenAI (GPT)
  - Google (Gemini)
  - **Self-hosted** (Ollama local, Groq private, etc.)
- ✅ Sem lock-in — dados sempre em JSON estruturado

---

## 📊 Exemplo de Output

**Vulnerability Reachable (MAJOR fix)**:
```json
{
  "cve_id": "CVE-2023-54321",
  "package": "lodash",
  "is_reachable": true,
  "remediation": {
    "type": "MAJOR",
    "description": "Upgrade to lodash@5.x (breaking changes)",
    "changes_needed": [
      "Replace _.assign() with Object.assign()",
      "Update src/handlers/data.js:112"
    ],
    "effort_estimate": "2-4 hours"
  }
}
```

**Vulnerability Not Reachable (ignore)**:
```json
{
  "cve_id": "CVE-2023-99999",
  "package": "uuid",
  "is_reachable": false,
  "reason": "Package imported but vulnerable function (custom seeding) never called",
  "remediation": {
    "type": "OPTIONAL",
    "description": "Monitor but no action needed"
  }
}
```

---

## 📚 Documentação

- **[README.md](README.md)** — Overview e comandos
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** — 10 test cases detalhados
- **[V2_ROADMAP.md](V2_ROADMAP.md)** — O que vem em V2

---

## 🤝 Feedback

**Como reportar**:

1. **Issue Crítica** (crash, não funciona):
   → https://github.com/lucasvsantos591-hue/vra-project/issues

2. **Feedback Geral** (feature request, idea):
   → [Formulário em TESTING_GUIDE.md](TESTING_GUIDE.md#-feedback-form)

3. **Rápido/Slack/Teams**:
   → Compartilha com Lucas (seu lado)

---

## ⏱️ Timeline

- **Agora**: Setup e testes (30-60 min)
- **Próx. 1-2 semanas**: Feedback ao time VRA
- **Mês 1-2**: V1 final + ajustes baseado em feedback
- **Mês 2-3**: V2 (scan-repo, GitHub integration, CI/CD)

---

## 🎉 Prêmio

Aquele que mais contribuir com feedback de qualidade ganha:
- ✨ Menção especial no README
- 🏆 Foto no hall of fame V2
- 🎁 TBD (vamos negociar)

---

## ❓ FAQ

**P: Roda com Python/Go/Java?**
R: Hoje suportamos JS/TS (Babel). Python está em desenvolvimento. Go/Java/Rust no roadmap V2+.

**P: E se usarmos Ollama (self-hosted)?**
R: Perfeito! `--ai-provider custom --ai-base-url http://localhost:11434/v1`. Zero custo.

**P: Posso submeter um projeto privado?**
R: Claro. Estamos pedindo feedback de vocês — repositório privado fica privado.

**P: Quanto custa?**
R: VRA é **gratuito** (open-source MIT). IA você paga diretamente (Claude, OpenAI, Gemini). Self-hosted é free.

**P: Pronto para produção?**
R: V1 está **beta**. Com seu feedback, fica production-ready em V1.1.

---

## 🚀 Let's Go!

1. Clone: https://github.com/lucasvsantos591-hue/vra-project
2. Leia: [TESTING_GUIDE.md](TESTING_GUIDE.md)
3. Teste: 30 min, 10 casos
4. Feedback: [Formulário](TESTING_GUIDE.md#-feedback-form)

Esperamos seu feedback! 💪

---

**Dúvidas?**
→ Issues no repo ou direto com Lucas

**Status**:
- V1: ✅ Pronto para beta testing
- V2: 🚀 Em planning (feedback seu vai priorizar features)

---

Obrigado por testar! 🙏
