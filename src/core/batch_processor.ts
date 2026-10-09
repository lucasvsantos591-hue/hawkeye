import { AnalysisEngine } from './analysis_engine.js';
import { mapLimit } from './http.js';
import { discoverProjects } from './project_discovery.js';
import { AnalysisResult } from '../types/analysis-result.js';
import * as fs from 'fs';
import * as path from 'path';

export interface BatchJob {
  projectPath: string;
  level?: 1 | 2 | 3;
  includeDev?: boolean;
  /** Run mvn/gradle (executes the project's build scripts). Default false. */
  allowBuildTool?: boolean;
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
  addJobsFromDirectory(basePath: string, defaults: Omit<BatchJob, 'projectPath'> = {}): void {
    try {
      const entries = fs.readdirSync(basePath);

      for (const entry of entries) {
        const fullPath = path.join(basePath, entry);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
          if (discoverProjects(fullPath).length > 0) {
            this.addJob({ level: 2, ...defaults, projectPath: fullPath });
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

    process.stderr.write(`🚀 Batch: ${this.jobs.length} projects, ${this.maxConcurrent} at a time\n`);
    await mapLimit(this.jobs, this.maxConcurrent, job => this.processJob(job, results));

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
      process.stderr.write(`⏳ Analyzing: ${projectName}\n`);

      const engine = new AnalysisEngine({
        projectPath: job.projectPath,
        level: job.level || 2,
        includeDev: job.includeDev,
        allowBuildTool: job.allowBuildTool === true,
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
      process.stderr.write(`✅ Completed: ${projectName} (${duration}s)\n`);
    } catch (error) {
      results.set(projectName, error as Error);
      process.stderr.write(`❌ Failed: ${projectName} - ${(error as Error).message}\n`);
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
