import { AnalysisEngine } from './analysis_engine.js';
import { AnalysisResult } from '../types/analysis-result.js';
import * as fs from 'fs';
import * as path from 'path';

export interface BatchJob {
  projectPath: string;
  level?: 1 | 2 | 3;
  language?: string;
  outputFile?: string;
}

export interface BatchResult {
  totalProjects: number;
  successfulAnalysis: number;
  failedAnalysis: number;
  results: Map<string, AnalysisResult | Error>;
  totalTime: number;
  averageRiskScore: number;
}

/**
 * Batch processor for analyzing multiple projects
 */
export class BatchProcessor {
  private maxConcurrent: number;
  private jobs: BatchJob[] = [];

  constructor(maxConcurrent: number = 4) {
    this.maxConcurrent = maxConcurrent;
  }

  /**
   * Add a job to the batch
   */
  addJob(job: BatchJob): void {
    this.jobs.push(job);
  }

  /**
   * Add jobs from a directory
   */
  addJobsFromDirectory(basePath: string): void {
    try {
      const entries = fs.readdirSync(basePath);

      for (const entry of entries) {
        const fullPath = path.join(basePath, entry);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
          // Check if it's a valid project (has package.json)
          if (fs.existsSync(path.join(fullPath, 'package.json'))) {
            this.addJob({
              projectPath: fullPath,
              level: 2,
            });
          }
        }
      }
    } catch (error) {
      console.error(`Failed to read directory ${basePath}:`, error);
    }
  }

  /**
   * Process all jobs
   */
  async process(): Promise<BatchResult> {
    const startTime = Date.now();
    const results = new Map<string, AnalysisResult | Error>();
    let successfulAnalysis = 0;
    let totalRiskScore = 0;

    console.log(`\n🚀 Starting batch processing: ${this.jobs.length} projects`);
    console.log(`📊 Max concurrent: ${this.maxConcurrent}\n`);

    // Process jobs with concurrency control
    const queue = [...this.jobs];
    const active: Promise<void>[] = [];

    while (queue.length > 0 || active.length > 0) {
      // Start new jobs if under limit
      while (active.length < this.maxConcurrent && queue.length > 0) {
        const job = queue.shift()!;
        const promise = this.processJob(job, results);
        active.push(promise);
      }

      // Wait for at least one to complete
      if (active.length > 0) {
        await Promise.race(active);
        // Remove completed promises
        for (let i = active.length - 1; i >= 0; i--) {
          if ((active[i] as any).resolved) {
            active.splice(i, 1);
          }
        }
      }
    }

    // Calculate statistics
    for (const result of results.values()) {
      if (!(result instanceof Error)) {
        successfulAnalysis++;
        totalRiskScore += result.overall_risk_score;
      }
    }

    const totalTime = Date.now() - startTime;
    const averageRiskScore =
      successfulAnalysis > 0 ? totalRiskScore / successfulAnalysis : 0;

    return {
      totalProjects: this.jobs.length,
      successfulAnalysis,
      failedAnalysis: this.jobs.length - successfulAnalysis,
      results,
      totalTime,
      averageRiskScore,
    };
  }

  /**
   * Process a single job
   */
  private async processJob(
    job: BatchJob,
    results: Map<string, AnalysisResult | Error>,
  ): Promise<void> {
    const projectName = path.basename(job.projectPath);
    const startTime = Date.now();

    try {
      console.log(`⏳ Analyzing: ${projectName}`);

      const engine = new AnalysisEngine({
        projectPath: job.projectPath,
        level: job.level || 2,
        language: job.language,
      });

      const result = await engine.analyze();
      results.set(projectName, result);

      // Save if output file specified
      if (job.outputFile) {
        fs.writeFileSync(
          job.outputFile,
          JSON.stringify(result, null, 2),
        );
      }

      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      console.log(`✅ Completed: ${projectName} (${duration}s)`);
    } catch (error) {
      results.set(projectName, error as Error);
      console.error(`❌ Failed: ${projectName} - ${(error as Error).message}`);
    }
  }

  /**
   * Get batch summary
   */
  static summarizeResults(result: BatchResult): string {
    return `
📊 Batch Processing Summary
${'='.repeat(50)}
Total Projects:     ${result.totalProjects}
Successful:         ${result.successfulAnalysis} ✅
Failed:             ${result.failedAnalysis} ❌
Success Rate:       ${((result.successfulAnalysis / result.totalProjects) * 100).toFixed(1)}%
Average Risk Score: ${result.averageRiskScore.toFixed(1)}/100
Total Time:         ${(result.totalTime / 1000).toFixed(2)}s
Average Time/Project: ${(result.totalTime / result.totalProjects / 1000).toFixed(2)}s
${'='.repeat(50)}
`;
  }
}
