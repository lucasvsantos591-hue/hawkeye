import * as fs from 'fs';
import * as path from 'path';

export interface ReachabilityAnalysis {
  packageName: string;
  currentVersion: string;
  level1IsReachable: boolean; // Is package imported?
  level2IsReachable: boolean; // Is vulnerable function called?
  importPaths: string[]; // Files that import this package
  callChain?: string[]; // Call chain from entry point to vulnerable function
}

export class ReachabilityAnalyzer {
  private projectPath: string;
  private sourceFiles: Map<string, string> = new Map(); // Cache for file contents

  constructor(projectPath: string) {
    this.projectPath = projectPath;
  }

  /**
   * Level 1 Analysis: Detect if package is imported
   */
  async analyzeLevel1(packageName: string): Promise<ReachabilityAnalysis> {
    const importPaths = this.findImports(packageName);

    return {
      packageName,
      currentVersion: '',
      level1IsReachable: importPaths.length > 0,
      level2IsReachable: false,
      importPaths,
    };
  }

  /**
   * Level 2 Analysis: Build call graph and check function reachability
   */
  async analyzeLevel2(
    packageName: string,
    vulnerableFunction: string,
    entryPoint: string = 'src/index.ts',
  ): Promise<ReachabilityAnalysis> {
    const importPaths = this.findImports(packageName);

    if (importPaths.length === 0) {
      return {
        packageName,
        currentVersion: '',
        level1IsReachable: false,
        level2IsReachable: false,
        importPaths: [],
      };
    }

    // Try to find call chain from entry point to vulnerable function
    const callChain = await this.traceCallChain(
      entryPoint,
      packageName,
      vulnerableFunction,
    );

    return {
      packageName,
      currentVersion: '',
      level1IsReachable: true,
      level2IsReachable: callChain.length > 0,
      importPaths,
      callChain,
    };
  }

  /**
   * Find all imports of a package in the project
   */
  private findImports(packageName: string): string[] {
    const results: string[] = [];
    const srcDir = path.join(this.projectPath, 'src');

    if (!fs.existsSync(srcDir)) {
      return results;
    }

    const walkDir = (dir: string) => {
      try {
        const files = fs.readdirSync(dir);

        for (const file of files) {
          const filePath = path.join(dir, file);
          const stat = fs.statSync(filePath);

          if (stat.isDirectory()) {
            if (!file.startsWith('.') && file !== 'node_modules') {
              walkDir(filePath);
            }
          } else if (file.endsWith('.ts') || file.endsWith('.js')) {
            if (this.fileImportsPackage(filePath, packageName)) {
              results.push(filePath.replace(this.projectPath, '.'));
            }
          }
        }
      } catch (error) {
        // Ignore directory read errors
      }
    };

    walkDir(srcDir);
    return results;
  }

  /**
   * Check if a file imports a specific package
   */
  private fileImportsPackage(filePath: string, packageName: string): boolean {
    const content = this.getFileContent(filePath);

    // Simple regex to find import/require statements
    const importPatterns = [
      `import.*from\\s+['"](${packageName})['"'](\\s|;|$)`,
      `require\\s*\\(\\s*['"](${packageName})['"]\\s*\\)`,
      `import\\s+['"](${packageName})['"]`,
    ];

    for (const pattern of importPatterns) {
      if (new RegExp(pattern).test(content)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Trace call chain from entry point to vulnerable function
   * Returns call chain if found, empty array otherwise
   */
  private async traceCallChain(
    entryPoint: string,
    packageName: string,
    vulnerableFunction: string,
  ): Promise<string[]> {
    // This is a simplified implementation
    // A full implementation would need to:
    // 1. Parse the entire codebase into an AST
    // 2. Build a complete call graph
    // 3. Search for paths from entry point to vulnerable function

    const entryPath = path.join(this.projectPath, entryPoint);
    if (!fs.existsSync(entryPath)) {
      return [];
    }

    const entryContent = this.getFileContent(entryPath);

    // Check if entry point imports the package
    if (!this.fileImportsPackage(entryPath, packageName)) {
      return [];
    }

    // Look for function calls that might reach the vulnerable function
    // For now, return empty (implementation would be more complex)
    const callChainFound = this.findFunctionCallChain(
      entryContent,
      vulnerableFunction,
    );

    if (callChainFound) {
      return [
        `${entryPoint}:main`,
        `${packageName}.${vulnerableFunction}`,
      ];
    }

    return [];
  }

  /**
   * Simple check if content references a function
   */
  private findFunctionCallChain(content: string, functionName: string): boolean {
    const pattern = new RegExp(`\\b${functionName}\\s*\\(`, 'g');
    return pattern.test(content);
  }

  /**
   * Get file content (with caching)
   */
  private getFileContent(filePath: string): string {
    if (!this.sourceFiles.has(filePath)) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        this.sourceFiles.set(filePath, content);
        return content;
      } catch {
        return '';
      }
    }

    return this.sourceFiles.get(filePath) || '';
  }

  /**
   * Clear cache (useful for large projects)
   */
  clearCache(): void {
    this.sourceFiles.clear();
  }
}
