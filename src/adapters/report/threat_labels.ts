import type { AnalysisResult, EpssStatus, KevStatus, VulnerabilityInfo } from '../../types/analysis-result.js';

/**
 * KEV status of a finding. Results written before kev_status existed only carry is_exploited_in_wild,
 * so the status is inferred from it and from the scan warnings (a failed lookup is "not checked").
 */
export function kevStatusOf(v: VulnerabilityInfo, result?: AnalysisResult): KevStatus {
  if (v.kev_status) return v.kev_status;
  if (v.is_exploited_in_wild) return 'listed';
  if (![v.cve_id, ...(v.aliases ?? [])].some(id => id?.startsWith('CVE-'))) return 'no_cve';
  if (v.is_exploited_in_wild === undefined) return 'not_checked';
  if (result?.scan?.threat_intel?.kev.status === 'failed') return 'not_checked';
  if (result?.scan?.warnings.some(w => w.startsWith('CISA KEV lookup failed'))) return 'not_checked';
  return 'not_listed';
}

const LABELS: Record<'en' | 'pt', Record<KevStatus, string>> = {
  en: {
    listed: 'Listed: exploited in the wild',
    not_listed: 'Not listed: no known exploitation',
    not_checked: 'Not checked: catalog lookup failed',
    no_cve: 'Not applicable: advisory has no CVE id',
  },
  pt: {
    listed: 'Listada: exploração ativa confirmada',
    not_listed: 'Não listada: sem exploração conhecida',
    not_checked: 'Não verificada: falha ao consultar o catálogo',
    no_cve: 'Não se aplica: advisory sem CVE',
  },
};

export function kevLabel(v: VulnerabilityInfo, result?: AnalysisResult, lang: 'en' | 'pt' = 'en'): string {
  const status = kevStatusOf(v, result);
  const label = LABELS[lang][status];
  if (status !== 'listed' || !v.kev_date_added) return label;
  return `${label} (${lang === 'pt' ? 'incluída em' : 'added'} ${v.kev_date_added})`;
}

/** One line describing which KEV catalog was checked, for the scan section of a report. */
export function kevCatalogLine(result: AnalysisResult, lang: 'en' | 'pt' = 'en'): string | null {
  const info = result.scan?.threat_intel?.kev;
  if (!info) return null;
  if (info.status === 'failed') {
    return lang === 'pt' ? 'CISA KEV: catálogo indisponível, nenhuma CVE foi verificada.' : 'CISA KEV: catalog unavailable, no CVE was checked.';
  }
  const counts: Record<KevStatus, number> = { listed: 0, not_listed: 0, not_checked: 0, no_cve: 0 };
  for (const f of result.results) counts[kevStatusOf(f.vulnerability, result)]++;
  const version = info.catalog_version ? ` ${info.catalog_version}` : '';
  const entries = info.entries !== undefined ? ` (${info.entries} CVEs)` : '';
  return lang === 'pt'
    ? `CISA KEV: catálogo${version}${entries} consultado. ${counts.listed} listada(s), ${counts.not_listed} não listada(s), ${counts.no_cve} sem CVE.`
    : `CISA KEV: catalog${version}${entries} checked. ${counts.listed} listed, ${counts.not_listed} not listed, ${counts.no_cve} without a CVE id.`;
}

/**
 * EPSS status of a finding. Results written before epss_status existed only carry epss_score, so the
 * status is inferred from it and from the scan warnings (a failed lookup is "not checked").
 */
export function epssStatusOf(v: VulnerabilityInfo, result?: AnalysisResult): EpssStatus {
  if (v.epss_status) return v.epss_status;
  if (v.epss_score !== undefined) return 'scored';
  if (![v.cve_id, ...(v.aliases ?? [])].some(id => id?.startsWith('CVE-'))) return 'no_cve';
  if (result?.scan?.threat_intel?.epss?.status === 'failed') return 'not_checked';
  if (result?.scan?.warnings.some(w => w.startsWith('EPSS lookup failed'))) return 'not_checked';
  return 'not_scored';
}

const EPSS_LABELS: Record<'en' | 'pt', Record<Exclude<EpssStatus, 'scored'>, string>> = {
  en: {
    not_scored: 'Not scored yet: FIRST EPSS has no score for this CVE (usually a CVE published in the last few days)',
    not_checked: 'Not checked: EPSS lookup failed',
    no_cve: 'Not applicable: advisory has no CVE id',
  },
  pt: {
    not_scored: 'Ainda sem score: o FIRST EPSS não tem score para esta CVE (em geral, CVE publicada há poucos dias)',
    not_checked: 'Não verificado: falha ao consultar o EPSS',
    no_cve: 'Não se aplica: advisory sem CVE',
  },
};

export function epssLabel(v: VulnerabilityInfo, result?: AnalysisResult, lang: 'en' | 'pt' = 'en'): string {
  const status = epssStatusOf(v, result);
  if (status !== 'scored' || v.epss_score === undefined) return EPSS_LABELS[lang][status === 'scored' ? 'not_scored' : status];
  const percentile = v.epss_percentile !== undefined ? ` · p${Math.round(v.epss_percentile)}` : '';
  return `${v.epss_score.toFixed(2)}%${percentile}`;
}

/** One line summarising the EPSS lookup, for the scan section of a report. */
export function epssSummaryLine(result: AnalysisResult, lang: 'en' | 'pt' = 'en'): string | null {
  if (!result.scan?.threat_intel?.epss) return null;
  if (result.scan.threat_intel.epss.status === 'failed') {
    return lang === 'pt' ? 'FIRST EPSS: API indisponível, nenhuma CVE foi verificada.' : 'FIRST EPSS: API unavailable, no CVE was checked.';
  }
  const counts: Record<EpssStatus, number> = { scored: 0, not_scored: 0, not_checked: 0, no_cve: 0 };
  for (const f of result.results) counts[epssStatusOf(f.vulnerability, result)]++;
  return lang === 'pt'
    ? `FIRST EPSS consultado. ${counts.scored} com score, ${counts.not_scored} ainda sem score, ${counts.no_cve} sem CVE.`
    : `FIRST EPSS checked. ${counts.scored} scored, ${counts.not_scored} not scored yet, ${counts.no_cve} without a CVE id.`;
}
