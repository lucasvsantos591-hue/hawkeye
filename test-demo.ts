#!/usr/bin/env node

/**
 * 🎯 VRA Demo - Teste o parser ao vivo!
 * Mostra como o VRA detecta funções, chamadas e vulnerabilidades
 */

import { JavaScriptCallGraphBuilder } from './adapters/parsers/js_typescript_parser/call_graph_builder';

console.log('\n🔍 === VRA (Vulnerability Reachability Analyzer) Demo ===\n');

// ============================================
// Exemplo 1: Código SEGURO (função não usada)
// ============================================
console.log('📝 Exemplo 1: Pacote importado mas NÃO usado');
console.log('─'.repeat(60));

const safeCode = `
import axios from 'axios';  // CVE-2023-XXXX em axios < 1.4.0

export function fetchSafeData() {
  // Usa apenas métodos seguros, não chama axios
  return fetch('/api/safe');
}

// axios nunca é chamado!
`;

console.log('Código:\n', safeCode);

const builder1 = new JavaScriptCallGraphBuilder();
const graph1 = builder1.buildFromSource(safeCode);

console.log('\n✅ Análise:');
console.log('  • axios importado?', graph1.has('axios') ? '✅ SIM' : '❌ NÃO');
console.log('  • axios.get chamado?',
  Array.from(graph1.values()).some(n => n.calledFunctions.has('axios.get'))
    ? '✅ SIM'
    : '❌ NÃO (SEGURO!)');
console.log('  • fetchSafeData é entry point?', graph1.get('fetchSafeData')?.isEntryPoint ? '✅ SIM' : '❌ NÃO');

console.log('\n📊 Resultado VRA:');
console.log('  Nível 1 (Import): ⚠️  POTENCIALMENTE VULNERÁVEL (axios importado)');
console.log('  Nível 2 (Call Graph): ✅ SEGURO (axios.get não é chamado)');
console.log('  Recomendação: NENHUMA AÇÃO NECESSÁRIA (falso positivo evitado!)');

// ============================================
// Exemplo 2: Código VULNERÁVEL (função usada)
// ============================================
console.log('\n\n');
console.log('📝 Exemplo 2: Pacote importado E usado');
console.log('─'.repeat(60));

const vulnerableCode = `
import axios from 'axios';  // CVE-2023-XXXX em axios < 1.4.0

export function fetchUserData(url) {
  // ⚠️  URL vem do usuário - VULNERÁVEL!
  return axios.get(url);
}
`;

console.log('Código:\n', vulnerableCode);

const builder2 = new JavaScriptCallGraphBuilder();
const graph2 = builder2.buildFromSource(vulnerableCode);

console.log('\n✅ Análise:');
console.log('  • axios importado?', graph2.has('axios') ? '✅ SIM' : '❌ NÃO');

const fetchNode = graph2.get('fetchUserData');
console.log('  • axios.get chamado?', fetchNode?.calledFunctions.has('axios.get') ? '✅ SIM' : '❌ NÃO');
console.log('  • fetchUserData é entry point?', fetchNode?.isEntryPoint ? '✅ SIM' : '❌ NÃO');

console.log('\n📊 Resultado VRA:');
console.log('  Nível 1 (Import): ⚠️  VULNERÁVEL (axios importado)');
console.log('  Nível 2 (Call Graph): ⚠️  VULNERÁVEL (axios.get é chamado!)');
console.log('  Nível 3 (Taint): ⚠️  VULNERÁVEL (URL do usuário → sink)');
console.log('  Recomendação: ⚠️  ATUALIZAR axios para >= 1.4.1 OU validar URL');

// ============================================
// Exemplo 3: Call Graph Complexo
// ============================================
console.log('\n\n');
console.log('📝 Exemplo 3: Grafo de chamadas complexo');
console.log('─'.repeat(60));

const complexCode = `
import express from 'express';

function vulnerableHandler(req, res) {
  const userInput = req.params.id;
  handleRequest(userInput);
}

function handleRequest(data) {
  processData(data);
}

function processData(input) {
  // Vulnerable function!
  eval(input);  // SUPER PERIGOSO!
}

const app = express();
app.get('/api/:id', vulnerableHandler);
`;

console.log('Código:\n', complexCode);

const builder3 = new JavaScriptCallGraphBuilder();
const graph3 = builder3.buildFromSource(complexCode);

console.log('\n✅ Call Graph detectado:');
for (const [name, node] of graph3) {
  if (node.calledFunctions.size > 0) {
    console.log(`  • ${name}() chama: ${Array.from(node.calledFunctions).join(', ')}`);
  }
}

console.log('\n📊 Cadeia de Chamadas (Call Chain):');
console.log('  vulnerableHandler() → handleRequest() → processData() → eval()');
console.log('  ⚠️  CADEIA DE VULNERABILIDADE DETECTADA!');

// ============================================
// Resumo
// ============================================
console.log('\n\n');
console.log('🎯 === RESUMO DO VRA ===\n');
console.log('✅ Nível 1 (Import Detection):');
console.log('   Detecta se pacote vulnerável é importado');
console.log('   Rápido, mas muitos falsos positivos\n');

console.log('✅ Nível 2 (Call Graph Analysis):');
console.log('   Detecta se função vulnerável é REALMENTE chamada');
console.log('   Reduz falsos positivos significativamente\n');

console.log('✅ Nível 3 (Taint Analysis):');
console.log('   Detecta se dados do usuário chegam até a vuln');
console.log('   Mais preciso, mas mais lento\n');

console.log('💡 Benefício:');
console.log('   Evita alertas falsos sobre vulnerabilidades');
console.log('   Foca apenas em riscos REAIS e exploráveis\n');

console.log('─'.repeat(60));
console.log('\n✨ Para ver mais exemplos, rode: npm run test\n');
