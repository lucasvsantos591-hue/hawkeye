import * as fs from 'fs';
import * as path from 'path';

/**
 * File access confined to the scanned directory. Manifests, lockfiles and `-r`/`relativePath`
 * references come from the repository being analyzed, so a symlink or `../` path must not make
 * Hawkeye read (and echo back in warnings) files outside it.
 */
export class ProjectFs {
  readonly root: string;

  constructor(root: string) {
    this.root = fs.realpathSync(root);
  }

  inside(file: string): boolean {
    try {
      const real = fs.realpathSync(file);
      return real === this.root || real.startsWith(this.root + path.sep);
    } catch {
      return false;
    }
  }

  exists(file: string): boolean {
    return fs.existsSync(file) && this.inside(file);
  }

  isDirectory(dir: string): boolean {
    return this.exists(dir) && fs.statSync(dir).isDirectory();
  }

  read(file: string): string {
    if (!this.inside(file)) {
      throw new Error(`refusing to read ${path.basename(file)}: it resolves outside the scanned directory`);
    }
    return fs.readFileSync(file, 'utf-8');
  }

  readdir(dir: string): string[] {
    if (!this.isDirectory(dir)) return [];
    try {
      return fs.readdirSync(dir);
    } catch {
      return [];
    }
  }
}
