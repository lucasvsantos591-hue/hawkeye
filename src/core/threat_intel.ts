import { CacheManager } from './cache_manager.js';
import { fetchJson } from './http.js';
import type { EpssStatus, KevCatalogInfo, KevStatus, VulnerabilityFinding } from '../types/analysis-result.js';

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

export interface KevCatalog {
  version?: string;
  released?: string;
  /** CVE id → date it was added to the catalog. */
  entries: Map<string, string>;
}

export interface ThreatIntel {
  /** null when the EPSS API could not be reached: scores are then unknown, not "not scored". */
  epss: Map<string, EpssScore> | null;
  /** null when the catalog could not be fetched: KEV status is then unknown, not "not listed". */
  kev: KevCatalog | null;
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
      return null;
    }),
    fetchKev(cache).catch(error => {
      warnings.push(`CISA KEV lookup failed: ${(error as Error).message}`);
      return null;
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

async function fetchKev(cache: CacheManager): Promise<KevCatalog> {
  type Stored = { version?: string; released?: string; entries: Array<[string, string]> };
  const cached = cache.get<Stored>('kev:catalog:v2');
  if (cached) return { version: cached.version, released: cached.released, entries: new Map(cached.entries) };
  const res = await fetchJson<{
    catalogVersion?: string;
    dateReleased?: string;
    vulnerabilities: Array<{ cveID: string; dateAdded?: string }>;
  }>(KEV_URL, { timeoutMs: 60_000 });
  const entries = (res.vulnerabilities ?? []).filter(v => v.cveID).map(v => [v.cveID, v.dateAdded ?? ''] as [string, string]);
  if (entries.length === 0) throw new Error('KEV catalog was empty');
  const stored: Stored = { version: res.catalogVersion, released: res.dateReleased, entries };
  cache.set('kev:catalog:v2', stored, TTL);
  return { version: stored.version, released: stored.released, entries: new Map(entries) };
}

/** KEV status of an advisory, matching its main CVE id and every CVE alias. */
export function kevLookup(cveIds: string[], kev: KevCatalog | null): { status: KevStatus; date_added?: string } {
  const cves = [...new Set(cveIds.filter(id => id.startsWith('CVE-')))];
  if (cves.length === 0) return { status: 'no_cve' };
  if (!kev) return { status: 'not_checked' };
  const hit = cves.find(id => kev.entries.has(id));
  if (!hit) return { status: 'not_listed' };
  const date = kev.entries.get(hit);
  return date ? { status: 'listed', date_added: date } : { status: 'listed' };
}

/** EPSS score of an advisory, from its main CVE id or the first CVE alias that has one. */
export function epssLookup(
  cveIds: string[],
  epss: Map<string, EpssScore> | null,
): { status: EpssStatus; score?: EpssScore } {
  const cves = [...new Set(cveIds.filter(id => id.startsWith('CVE-')))];
  if (cves.length === 0) return { status: 'no_cve' };
  if (!epss) return { status: 'not_checked' };
  const hit = cves.find(id => epss.has(id));
  return hit ? { status: 'scored', score: epss.get(hit)! } : { status: 'not_scored' };
}

/** Every CVE id of the given advisories (main id and aliases), for one lookup call. */
export function allCveIds(advisories: Array<{ cve_id: string; aliases?: string[] }>): string[] {
  return advisories.flatMap(a => [a.cve_id, ...(a.aliases ?? [])]);
}

export function threatIntelInfo(intel: ThreatIntel): { kev: KevCatalogInfo; epss: { source: string; status: 'checked' | 'failed' } } {
  return { kev: kevCatalogInfo(intel.kev), epss: { source: EPSS_URL, status: intel.epss ? 'checked' : 'failed' } };
}

export function kevCatalogInfo(kev: KevCatalog | null): KevCatalogInfo {
  if (!kev) return { source: KEV_URL, status: 'failed' };
  return {
    source: KEV_URL,
    status: 'checked',
    ...(kev.version ? { catalog_version: kev.version } : {}),
    ...(kev.released ? { date_released: kev.released } : {}),
    entries: kev.entries.size,
  };
}

/**
 * Writes EPSS and KEV data into findings. Every finding gets an explicit epss_status and kev_status, so a
 * report can show that each check ran even when the answer is "no score" or "not listed". A failed lookup
 * never erases what an earlier, successful check recorded.
 */
export function applyThreatIntel(findings: VulnerabilityFinding[], intel: ThreatIntel): void {
  for (const finding of findings) {
    const v = finding.vulnerability;
    const ids = [v.cve_id, ...(v.aliases ?? [])];

    const epss = epssLookup(ids, intel.epss);
    if (epss.status !== 'not_checked' || !v.epss_status || v.epss_status === 'not_checked') {
      if (epss.score) {
        v.epss_score = epss.score.score;
        v.epss_percentile = epss.score.percentile;
      } else if (epss.status !== 'not_checked') {
        delete v.epss_score;
        delete v.epss_percentile;
      }
      v.epss_status = epss.status;
    }

    const kev = kevLookup(ids, intel.kev);
    if (kev.status === 'not_checked' && v.kev_status && v.kev_status !== 'not_checked') continue;
    v.is_exploited_in_wild = kev.status === 'listed';
    v.kev_status = kev.status;
    if (kev.date_added) v.kev_date_added = kev.date_added;
    else delete v.kev_date_added;
  }
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}
