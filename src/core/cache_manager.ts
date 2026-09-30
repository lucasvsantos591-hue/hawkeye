import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export interface CacheEntry {
  key: string;
  value: any;
  hash?: string;
  timestamp: number;
  ttl?: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  cveHits: number;
  astHits: number;
  resultHits: number;
}

/**
 * Simple file-based cache manager (JSON format)
 * In production, this would use SQLite for better performance
 */
export class CacheManager {
  private cacheDir: string;
  private cache: Map<string, CacheEntry> = new Map();
  private stats: CacheStats = {
    hits: 0,
    misses: 0,
    cveHits: 0,
    astHits: 0,
    resultHits: 0,
  };

  constructor(cacheDir: string = './.hawkeye-cache') {
    this.cacheDir = cacheDir;
    this.initializeCacheDir();
    this.loadCacheFromDisk();
  }

  /**
   * Get a value from cache
   */
  get<T = any>(key: string): T | null {
    const entry = this.cache.get(key);

    if (!entry) {
      this.stats.misses++;
      return null;
    }

    // Check if cache entry has expired
    if (entry.ttl && Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      this.stats.misses++;
      return null;
    }

    this.stats.hits++;

    // Track specific cache types
    if (key.startsWith('cve:')) this.stats.cveHits++;
    if (key.startsWith('ast:')) this.stats.astHits++;
    if (key.startsWith('result:')) this.stats.resultHits++;

    return entry.value as T;
  }

  /**
   * Set a value in cache
   */
  set<T = any>(key: string, value: T, ttl?: number): void {
    this.cache.set(key, {
      key,
      value,
      timestamp: Date.now(),
      ttl,
    });
  }

  /**
   * Check if key exists in cache
   */
  has(key: string): boolean {
    return this.cache.has(key);
  }

  /**
   * Clear cache
   */
  clear(): void {
    this.cache.clear();
    this.stats = { hits: 0, misses: 0, cveHits: 0, astHits: 0, resultHits: 0 };
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const total = this.stats.hits + this.stats.misses;
    const hitRate = total > 0 ? (this.stats.hits / total) * 100 : 0;

    console.log(`📊 Cache Stats:`);
    console.log(`   Total Requests: ${total}`);
    console.log(`   Hit Rate: ${hitRate.toFixed(1)}%`);
    console.log(`   CVE Hits: ${this.stats.cveHits}`);
    console.log(`   AST Hits: ${this.stats.astHits}`);
    console.log(`   Result Hits: ${this.stats.resultHits}`);

    return this.stats;
  }

  /**
   * Cache key generators
   */
  static cveCacheKey(packageName: string, version: string): string {
    return `cve:${packageName}@${version}`;
  }

  static astCacheKey(filePath: string, hash: string): string {
    return `ast:${filePath}:${hash}`;
  }

  static resultCacheKey(lockfileHash: string, level: number): string {
    return `result:${lockfileHash}:L${level}`;
  }

  /**
   * Calculate hash of a file or string
   */
  static hashContent(content: string | Buffer): string {
    if (typeof content === 'string') {
      content = Buffer.from(content);
    }
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
  }

  /**
   * Calculate hash of a file on disk
   */
  static hashFile(filePath: string): string {
    const content = fs.readFileSync(filePath);
    return this.hashContent(content);
  }

  /**
   * Save cache to disk (for persistence between runs)
   */
  saveToDisk(): void {
    try {
      const cacheFile = path.join(this.cacheDir, 'cache.json');
      const cacheData = Array.from(this.cache.entries()).map(([, entry]) => entry);

      fs.writeFileSync(cacheFile, JSON.stringify(cacheData, null, 2));
    } catch (error) {
      console.error('Failed to save cache:', error);
    }
  }

  /**
   * Load cache from disk
   */
  private loadCacheFromDisk(): void {
    try {
      const cacheFile = path.join(this.cacheDir, 'cache.json');

      if (!fs.existsSync(cacheFile)) {
        return;
      }

      const data = JSON.parse(fs.readFileSync(cacheFile, 'utf-8'));

      for (const entry of data) {
        this.cache.set(entry.key, {
          key: entry.key,
          value: entry.value,
          timestamp: entry.timestamp,
          ttl: entry.ttl,
        });
      }
    } catch (error) {
      console.error('Failed to load cache:', error);
    }
  }

  /**
   * Initialize cache directory
   */
  private initializeCacheDir(): void {
    if (!fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  /**
   * Get cache directory path
   */
  getCacheDir(): string {
    return this.cacheDir;
  }

  /**
   * Get cache size (number of entries)
   */
  size(): number {
    return this.cache.size;
  }
}
