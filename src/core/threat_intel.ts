import { CacheManager } from './cache_manager.js';
import { fetchJson } from './http.js';

const EPSS_URL = process.env.HAWKEYE_EPSS_URL || 'https://api.first.org/data/v1/epss';
const KEV_URL =
  process.env.HAWKEYE_KEV_URL ||
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const TTL = 24 * 60 * 60 * 1000;
const EPSS_BATCH = 100;

export interface EpssScore {
  /** Probability of exploitation in the next 30 days, as a percentage (0-100). */
  score: number;
  /** Percentile among all scored CVEs (0-100). */
  percentile: number;
}

export interface ThreatIntel {
  epss: Map<string, EpssScore>;
  kev: Set<string>;
  warnings: string[];
}

/**
 * Looks up FIRST EPSS scores and CISA KEV membership. Failures degrade to "no data"
 * with a warning; they never produce made-up values.
 */
export async function lookupThreatIntel(cveIds: string[], cache: CacheManager): Promise<ThreatIntel> {
  const warnings: string[] = [];
  const cves = [...new Set(cveIds.filter(id => id.startsWith('CVE-')))];

  const [epss, kev] = await Promise.all([
    fetchEpss(cves, cache).catch(error => {
      warnings.push(`EPSS lookup failed: ${(error as Error).message}`);
      return new Map<string, EpssScore>();
    }),
    fetchKev(cache).catch(error => {
      warnings.push(`CISA KEV lookup failed: ${(error as Error).message}`);
      return new Set<string>();
    }),
  ]);
  return { epss, kev, warnings };
}

async function fetchEpss(cves: string[], cache: CacheManager): Promise<Map<string, EpssScore>> {
  const out = new Map<string, EpssScore>();
  const missing: string[] = [];
  for (const cve of cves) {
    const cached = cache.get<EpssScore | null>(`epss:${cve}`);
    if (cached === undefined) missing.push(cve);
    else if (cached) out.set(cve, cached);
  }

  for (let i = 0; i < missing.length; i += EPSS_BATCH) {
    const batch = missing.slice(i, i + EPSS_BATCH);
    const res = await fetchJson<{ data: Array<{ cve: string; epss: string; percentile: string }> }>(
      `${EPSS_URL}?cve=${batch.join(',')}`,
    );
    const found = new Set<string>();
    for (const row of res.data ?? []) {
      const score = { score: round(parseFloat(row.epss) * 100), percentile: round(parseFloat(row.percentile) * 100) };
      if (Number.isNaN(score.score)) continue;
      out.set(row.cve, score);
      found.add(row.cve);
      cache.set(`epss:${row.cve}`, score, TTL);
    }
    for (const cve of batch) if (!found.has(cve)) cache.set(`epss:${cve}`, null, TTL);
  }
  return out;
}

async function fetchKev(cache: CacheManager): Promise<Set<string>> {
  const cached = cache.get<string[]>('kev:catalog');
  if (cached) return new Set(cached);
  const res = await fetchJson<{ vulnerabilities: Array<{ cveID: string }> }>(KEV_URL, { timeoutMs: 60_000 });
  const ids = (res.vulnerabilities ?? []).map(v => v.cveID).filter(Boolean);
  if (ids.length === 0) throw new Error('KEV catalog was empty');
  cache.set('kev:catalog', ids, TTL);
  return new Set(ids);
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}
