import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';

interface CacheEntry {
  value: unknown;
  expiresAt: number;
}

export function defaultCacheDir(): string {
  return process.env.HAWKEYE_CACHE_DIR || path.join(os.homedir(), '.cache', 'hawkeye');
}

/**
 * JSON-file cache for remote data (advisories, EPSS, KEV). Never caches analysis
 * results: those depend on source code and must always be recomputed.
 */
export class CacheManager {
  private readonly file: string | null;
  private entries = new Map<string, CacheEntry>();
  private dirty = false;

  constructor(cacheDir: string | null = defaultCacheDir()) {
    this.file = cacheDir ? path.join(cacheDir, 'cache.json') : null;
    if (!this.file) return;
    try {
      const data = JSON.parse(fs.readFileSync(this.file, 'utf-8')) as Record<string, CacheEntry>;
      const now = Date.now();
      for (const [key, entry] of Object.entries(data)) {
        if (entry && entry.expiresAt > now) this.entries.set(key, entry);
      }
    } catch {
      // Missing or corrupt cache: start empty.
    }
  }

  get<T>(key: string): T | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.value as T;
  }

  set(key: string, value: unknown, ttlMs: number): void {
    this.entries.set(key, { value, expiresAt: Date.now() + ttlMs });
    this.dirty = true;
  }

  save(): void {
    if (!this.file || !this.dirty) return;
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const tmp = `${this.file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.entries)));
      fs.renameSync(tmp, this.file);
      this.dirty = false;
    } catch (error) {
      process.stderr.write(`⚠️  Could not write cache ${this.file}: ${(error as Error).message}\n`);
    }
  }

  static hashContent(content: string | Buffer): string {
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
  }
}
