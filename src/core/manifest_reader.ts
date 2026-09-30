import * as fs from 'fs';
import * as path from 'path';

export interface PackageDependency {
  name: string;
  version: string;
  isDev: boolean;
}

export interface ProjectManifest {
  projectPath: string;
  packageJsonPath: string;
  lockfilePath?: string;
  lockfileType?: 'package-lock.json' | 'yarn.lock' | 'pnpm-lock.yaml';
  dependencies: PackageDependency[];
}

export class ManifestReader {
  /**
   * Read project manifest (package.json + lockfile)
   */
  static readProjectManifest(projectPath: string): ProjectManifest {
    const packageJsonPath = path.join(projectPath, 'package.json');

    if (!fs.existsSync(packageJsonPath)) {
      throw new Error(`package.json not found in ${projectPath}`);
    }

    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    const dependencies: PackageDependency[] = [];

    // Collect direct dependencies
    if (packageJson.dependencies) {
      for (const [name, version] of Object.entries(packageJson.dependencies)) {
        dependencies.push({
          name,
          version: String(version),
          isDev: false,
        });
      }
    }

    // Collect dev dependencies
    if (packageJson.devDependencies) {
      for (const [name, version] of Object.entries(packageJson.devDependencies)) {
        dependencies.push({
          name,
          version: String(version),
          isDev: true,
        });
      }
    }

    // Detect lockfile
    const lockfilePath = this.detectLockfile(projectPath);
    let lockfileType: ProjectManifest['lockfileType'];

    if (lockfilePath) {
      if (lockfilePath.endsWith('package-lock.json')) {
        lockfileType = 'package-lock.json';
      } else if (lockfilePath.endsWith('yarn.lock')) {
        lockfileType = 'yarn.lock';
      } else if (lockfilePath.endsWith('pnpm-lock.yaml')) {
        lockfileType = 'pnpm-lock.yaml';
      }
    }

    return {
      projectPath,
      packageJsonPath,
      lockfilePath,
      lockfileType,
      dependencies,
    };
  }

  /**
   * Detect which lockfile exists in the project
   */
  private static detectLockfile(projectPath: string): string | undefined {
    const candidates = [
      'package-lock.json',
      'yarn.lock',
      'pnpm-lock.yaml',
    ];

    for (const candidate of candidates) {
      const filePath = path.join(projectPath, candidate);
      if (fs.existsSync(filePath)) {
        return filePath;
      }
    }

    return undefined;
  }

  /**
   * Get actual resolved version from lockfile (if available)
   */
  static getResolvedVersion(projectPath: string, packageName: string): string | undefined {
    const lockfilePath = path.join(projectPath, 'package-lock.json');

    if (!fs.existsSync(lockfilePath)) {
      return undefined;
    }

    try {
      const lockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf-8'));

      // npm package-lock.json structure
      if (lockfile.packages && lockfile.packages[`node_modules/${packageName}`]) {
        return lockfile.packages[`node_modules/${packageName}`].version;
      }

      return undefined;
    } catch {
      return undefined;
    }
  }
}
