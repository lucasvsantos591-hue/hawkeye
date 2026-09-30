import semver from 'semver';

export type Ecosystem = 'npm' | 'PyPI' | 'Maven';

const QUALIFIER_RANK: Record<string, number> = {
  dev: -7,
  alpha: -6,
  a: -6,
  beta: -5,
  b: -5,
  milestone: -4,
  m: -4,
  rc: -3,
  cr: -3,
  c: -3,
  pre: -3,
  preview: -3,
  snapshot: -2,
  '': 0,
  ga: 0,
  final: 0,
  release: 0,
  post: 1,
  sp: 1,
  p: 1,
  rev: 1,
  r: 1,
};

type Token = number | string;

function tokenize(version: string): Token[] {
  const clean = version.trim().toLowerCase().replace(/^v/, '').split('+')[0];
  const tokens: Token[] = [];
  for (const match of clean.matchAll(/\d+|[a-z]+/g)) {
    tokens.push(/^\d/.test(match[0]) ? Number(match[0]) : match[0]);
  }
  return tokens;
}

function rank(q: string): number {
  return QUALIFIER_RANK[q] ?? 0.5;
}

/** Orders versions for npm (semver), PyPI (PEP 440-ish) and Maven (ComparableVersion-ish). */
export function compareVersions(ecosystem: Ecosystem, a: string, b: string): number {
  if (ecosystem === 'npm' && semver.valid(a, true) && semver.valid(b, true)) {
    return semver.compare(a, b, true);
  }
  const ta = tokenize(a);
  const tb = tokenize(b);
  const len = Math.max(ta.length, tb.length);
  for (let i = 0; i < len; i++) {
    const x = ta[i];
    const y = tb[i];
    if (x === y) continue;
    if (x === undefined) return typeof y === 'number' ? (y === 0 ? 0 : -1) : rank(y) > 0 ? -1 : 1;
    if (y === undefined) return typeof x === 'number' ? (x === 0 ? 0 : 1) : rank(x) > 0 ? 1 : -1;
    if (typeof x === 'number' && typeof y === 'number') return x < y ? -1 : 1;
    if (typeof x === 'number') return 1;
    if (typeof y === 'number') return -1;
    const diff = rank(x) - rank(y);
    if (diff !== 0) return diff < 0 ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

export function majorOf(version: string): number {
  const first = tokenize(version)[0];
  return typeof first === 'number' ? first : 0;
}

/** PEP 503 normalized Python distribution name. */
export function normalizePyName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, '-');
}
