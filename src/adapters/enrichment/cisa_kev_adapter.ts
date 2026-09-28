import axios from 'axios';
import type { CISAKEVRecord } from '../../types/cve-enrichment.js';

/**
 * CISA Known Exploited Vulnerabilities (KEV) Catalog
 * Public API: https://www.cisa.gov/known-exploited-vulnerabilities
 *
 * Provides list of vulnerabilities actively being exploited in the wild
 */

const CISA_KEV_API = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

interface CISAKEVResponse {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: CISAKEVRecord[];
}

class CISAKEVAdapter {
  private cache: Map<string, CISAKEVRecord | null> = new Map();
  private catalogCache: CISAKEVRecord[] | null = null;
  private lastFetch: number = 0;
  private CACHE_TTL = 3600000; // 1 hour in ms

  async getCatalog(): Promise<CISAKEVRecord[]> {
    // Return cached if fresh
    if (this.catalogCache && Date.now() - this.lastFetch < this.CACHE_TTL) {
      return this.catalogCache;
    }

    try {
      const response = await axios.get<CISAKEVResponse>(CISA_KEV_API, {
        timeout: 10000,
      });

      this.catalogCache = response.data.vulnerabilities;
      this.lastFetch = Date.now();

      return this.catalogCache;
    } catch (error) {
      console.warn('⚠️ Failed to fetch CISA KEV catalog:', (error as Error).message);
      // Return empty array on failure
      return [];
    }
  }

  async isKnownExploited(cveId: string): Promise<CISAKEVRecord | null> {
    // Check cache first
    if (this.cache.has(cveId)) {
      return this.cache.get(cveId) || null;
    }

    try {
      const catalog = await this.getCatalog();
      const record = catalog.find((v) => v.cve_id === cveId);

      // Cache the result (even if null)
      this.cache.set(cveId, record || null);

      return record || null;
    } catch (error) {
      console.warn(`⚠️ Error checking CISA KEV for ${cveId}:`, (error as Error).message);
      return null;
    }
  }

  async enrichCVE(cveId: string) {
    const record = await this.isKnownExploited(cveId);

    if (!record) {
      return {
        is_known_exploited: false,
      };
    }

    return {
      is_known_exploited: true,
      vendor: record.vendor,
      product: record.product,
      vulnerability_name: record.vulnerability_name,
      date_added: record.date_added,
      due_date: record.due_date,
      is_ransomware: record.known_ransomware_campaign_use === 'Yes',
    };
  }

  clearCache() {
    this.cache.clear();
    this.catalogCache = null;
    this.lastFetch = 0;
  }
}

export const cisaKEVAdapter = new CISAKEVAdapter();
