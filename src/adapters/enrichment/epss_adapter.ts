import axios from 'axios';
import type { EPSSScore } from '../../types/cve-enrichment.js';

/**
 * FIRST EPSS (Exploit Prediction Scoring System)
 * Public API: https://api.first.org/epss/
 *
 * Provides probability scores for vulnerability exploitation
 */

const EPSS_API = 'https://api.first.org/data/v1/epss';

interface EPSSResponse {
  status: string;
  statusDetails: string;
  data: EPSSScore[];
}

class EPSSAdapter {
  private cache: Map<string, EPSSScore | null> = new Map();
  private CACHE_TTL = 3600000; // 1 hour in ms
  private lastFetch: number = 0;

  async getScore(cveId: string): Promise<EPSSScore | null> {
    // Check cache first
    if (this.cache.has(cveId)) {
      const cached = this.cache.get(cveId);
      // If cached and fresh, return it
      if (cached && Date.now() - this.lastFetch < this.CACHE_TTL) {
        return cached;
      }
    }

    try {
      const response = await axios.get<EPSSResponse>(EPSS_API, {
        params: {
          cve: cveId,
        },
        timeout: 10000,
      });

      if (response.data.status !== 'OK' || !response.data.data || response.data.data.length === 0) {
        this.cache.set(cveId, null);
        return null;
      }

      const score = response.data.data[0];
      this.cache.set(cveId, score);
      this.lastFetch = Date.now();

      return score;
    } catch (error) {
      console.warn(`⚠️ Failed to fetch EPSS score for ${cveId}:`, (error as Error).message);
      this.cache.set(cveId, null);
      return null;
    }
  }

  async enrichCVE(cveId: string) {
    const score = await this.getScore(cveId);

    if (!score) {
      return {
        score: 0,
        percentile: 0,
        date: new Date().toISOString().split('T')[0],
      };
    }

    return {
      score: score.epss,
      percentile: score.percentile,
      date: score.date,
    };
  }

  clearCache() {
    this.cache.clear();
    this.lastFetch = 0;
  }
}

export const epssAdapter = new EPSSAdapter();
