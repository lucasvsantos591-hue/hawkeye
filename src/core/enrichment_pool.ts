/**
 * Concurrency pool for managing HTTP requests to EPSS and CISA KEV APIs
 * Prevents rate limiting and provides retry/backoff strategies
 */
export class EnrichmentPool {
  private maxConcurrent: number;
  private requestTimeout: number;
  private maxRetries: number;
  private activeRequests: number = 0;
  private queue: Array<() => Promise<any>> = [];

  constructor(maxConcurrent: number = 5, requestTimeout: number = 30000, maxRetries: number = 3) {
    this.maxConcurrent = maxConcurrent;
    this.requestTimeout = requestTimeout;
    this.maxRetries = maxRetries;
  }

  /**
   * Execute a task with concurrency control
   */
  async execute<T>(task: () => Promise<T>): Promise<T> {
    if (this.activeRequests >= this.maxConcurrent) {
      // Queue task and wait
      return new Promise((resolve, reject) => {
        this.queue.push(async () => {
          try {
            const result = await this.executeWithRetry(task);
            resolve(result);
          } catch (error) {
            reject(error);
          }
        });
      });
    } else {
      return this.executeWithRetry(task);
    }
  }

  /**
   * Execute task with retry and backoff
   */
  private async executeWithRetry<T>(task: () => Promise<T>): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        this.activeRequests++;

        // Timeout wrapper
        const result = await Promise.race([
          task(),
          this.delay(this.requestTimeout).then(() => {
            throw new Error('Request timeout');
          }),
        ]);

        this.activeRequests--;
        this.processQueue();
        return result as T;
      } catch (error) {
        this.activeRequests--;
        lastError = error as Error;

        if (attempt < this.maxRetries - 1) {
          // Exponential backoff: 1s, 2s, 4s
          const backoffMs = Math.pow(2, attempt) * 1000;
          await this.delay(backoffMs);
        }
      }
    }

    throw lastError || new Error('Task failed after retries');
  }

  /**
   * Process queued tasks
   */
  private processQueue(): void {
    if (this.queue.length > 0 && this.activeRequests < this.maxConcurrent) {
      const task = this.queue.shift();
      if (task) {
        task().catch(error => {
          console.error('Queued task error:', error);
        });
      }
    }
  }

  /**
   * Delay utility
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Wait for all tasks to complete
   */
  async drain(): Promise<void> {
    while (this.activeRequests > 0 || this.queue.length > 0) {
      await this.delay(100);
    }
  }

  /**
   * Get pool status
   */
  getStatus() {
    return {
      activeRequests: this.activeRequests,
      queuedRequests: this.queue.length,
      maxConcurrent: this.maxConcurrent,
    };
  }
}

/**
 * EPSS (Exploit Prediction Scoring System) enrichment service
 */
export class EPSSEnricher {
  private pool: EnrichmentPool;
  private cache: Map<string, number> = new Map();

  constructor(pool?: EnrichmentPool) {
    this.pool = pool || new EnrichmentPool();
  }

  /**
   * Get EPSS score for a CVE (mocked for now)
   */
  async getEPSSScore(cveId: string): Promise<number> {
    // Check cache first
    if (this.cache.has(cveId)) {
      return this.cache.get(cveId)!;
    }

    // Execute with pool
    const score = await this.pool.execute(async () => {
      // Mock EPSS response (in production, would call real API)
      // API: https://api.first.org/data/v1/epss?cve=CVE-2023-12345
      const mockScores: Record<string, number> = {
        'CVE-2023-12345': 75.5,
        'CVE-2023-54321': 92.3,
        'CVE-2022-99999': 45.2,
      };

      return mockScores[cveId] ?? Math.random() * 100;
    });

    // Cache the result
    this.cache.set(cveId, score);
    return score;
  }

  /**
   * Get EPSS scores in batch (more efficient)
   */
  async getEPSSScoresBatch(cveIds: string[]): Promise<Map<string, number>> {
    const results = new Map<string, number>();

    // Process in batches to avoid rate limiting
    const batchSize = 10;

    for (let i = 0; i < cveIds.length; i += batchSize) {
      const batch = cveIds.slice(i, i + batchSize);

      await this.pool.execute(async () => {
        for (const cveId of batch) {
          if (!results.has(cveId)) {
            const score = await this.getEPSSScore(cveId);
            results.set(cveId, score);
          }
        }
      });
    }

    return results;
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear();
  }
}

/**
 * CISA KEV (Known Exploited Vulnerabilities) enrichment service
 */
export class CISAKEVEnricher {
  private pool: EnrichmentPool;
  private kevList: Set<string> = new Set();
  private isLoaded: boolean = false;

  constructor(pool?: EnrichmentPool) {
    this.pool = pool || new EnrichmentPool();
  }

  /**
   * Initialize KEV list (load from API or cache)
   */
  async initialize(): Promise<void> {
    if (this.isLoaded) {
      return;
    }

    await this.pool.execute(async () => {
      // Mock CISA KEV list
      // API: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
      const mockKEV = new Set([
        'CVE-2023-12345',
        'CVE-2023-54321',
        'CVE-2022-88888',
        'CVE-2021-77777',
      ]);

      this.kevList = mockKEV;
      this.isLoaded = true;
    });
  }

  /**
   * Check if CVE is in known exploited vulnerabilities list
   */
  async isExploitedInWild(cveId: string): Promise<boolean> {
    if (!this.isLoaded) {
      await this.initialize();
    }

    return this.kevList.has(cveId);
  }

  /**
   * Get all exploited CVEs
   */
  getExploitedCVEs(): string[] {
    return Array.from(this.kevList);
  }
}

/**
 * Vulnerability enrichment service
 * Combines EPSS, CISA KEV, and other data sources
 */
export class VulnerabilityEnricher {
  private epssEnricher: EPSSEnricher;
  private cisaEnricher: CISAKEVEnricher;
  private pool: EnrichmentPool;

  constructor(pool?: EnrichmentPool) {
    this.pool = pool || new EnrichmentPool();
    this.epssEnricher = new EPSSEnricher(this.pool);
    this.cisaEnricher = new CISAKEVEnricher(this.pool);
  }

  /**
   * Enrich vulnerability findings with EPSS scores and KEV status
   */
  async enrichFindings(findings: any[]): Promise<any[]> {
    // Initialize KEV list
    await this.cisaEnricher.initialize();

    // Collect all CVE IDs
    const cveIds = findings.map(f => f.vulnerability.cve_id);

    // Get EPSS scores in batch
    const epssScores = await this.epssEnricher.getEPSSScoresBatch(cveIds);

    // Enrich findings
    const enrichedFindings = findings.map(finding => ({
      ...finding,
      epss_score: epssScores.get(finding.vulnerability.cve_id),
      is_exploited_in_wild: this.cisaEnricher
        .getExploitedCVEs()
        .includes(finding.vulnerability.cve_id),
    }));

    return enrichedFindings;
  }

  /**
   * Get pool status
   */
  getPoolStatus() {
    return this.pool.getStatus();
  }

  /**
   * Wait for all enrichment tasks to complete
   */
  async drain(): Promise<void> {
    await this.pool.drain();
  }
}
