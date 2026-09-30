#!/usr/bin/env node

import * as http from 'http';
import * as url from 'url';
import * as fs from 'fs';
import { AnalysisEngine } from '../core/analysis_engine.js';
import { HTMLReportRenderer } from '../adapters/report/html_renderer.js';
import { SARIFRenderer } from '../adapters/report/sarif_renderer.js';
import { ContextLoader } from '../adapters/context/context_loader.js';

const PORT = process.env.HAWKEYE_PORT ? parseInt(process.env.HAWKEYE_PORT) : 3000;
const startTime = Date.now();

/**
 * Simple HTTP API Server for Hawkeye
 */
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url || '', true);
  const pathname = parsedUrl.pathname || '';
  const method = req.method || 'GET';

  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  try {
    // Health check
    if (pathname === '/api/health') {
      res.setHeader('Content-Type', 'application/json');
      res.writeHead(200);
      res.end(
        JSON.stringify({
          status: 'ok',
          version: '1.0.0',
          uptime: Math.floor((Date.now() - startTime) / 1000),
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    // Analyze endpoint
    if (pathname === '/api/analyze' && method === 'POST') {
      let body = '';

      req.on('data', chunk => {
        body += chunk.toString();
      });

      req.on('end', async () => {
        try {
          const data = JSON.parse(body);
          const projectPath = data.projectPath || '.';
          const level = data.level || 2;

          if (!fs.existsSync(projectPath)) {
            res.setHeader('Content-Type', 'application/json');
            res.writeHead(400);
            res.end(
              JSON.stringify({
                error: 'Project path not found',
                projectPath,
              }),
            );
            return;
          }

          const engine = new AnalysisEngine({
            projectPath,
            level,
            language: data.language,
          });

          const result = await engine.analyze();

          res.setHeader('Content-Type', 'application/json');
          res.writeHead(200);
          res.end(JSON.stringify(result));
        } catch (error) {
          res.setHeader('Content-Type', 'application/json');
          res.writeHead(500);
          res.end(
            JSON.stringify({
              error: (error as Error).message,
            }),
          );
        }
      });
      return;
    }

    // Report endpoint
    if (pathname === '/api/report' && method === 'POST') {
      let body = '';

      req.on('data', chunk => {
        body += chunk.toString();
      });

      req.on('end', async () => {
        try {
          const data = JSON.parse(body);
          const analysisResult = data.analysisResult;
          const format = data.format || 'html';
          const projectPath = data.projectPath || '.';

          const context = ContextLoader.loadContext(projectPath);

          let report: string;

          if (format === 'html') {
            const renderer = new HTMLReportRenderer(analysisResult, context);
            report = renderer.render();
            res.setHeader('Content-Type', 'text/html');
          } else if (format === 'sarif') {
            const renderer = new SARIFRenderer(analysisResult);
            report = renderer.render();
            res.setHeader('Content-Type', 'application/json');
          } else {
            report = JSON.stringify(analysisResult, null, 2);
            res.setHeader('Content-Type', 'application/json');
          }

          res.writeHead(200);
          res.end(report);
        } catch (error) {
          res.setHeader('Content-Type', 'application/json');
          res.writeHead(500);
          res.end(
            JSON.stringify({
              error: (error as Error).message,
            }),
          );
        }
      });
      return;
    }

    // Not found
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(404);
    res.end(
      JSON.stringify({
        error: 'Not found',
        path: pathname,
        availableEndpoints: [
          'GET /api/health',
          'POST /api/analyze',
          'POST /api/report',
        ],
      }),
    );
  } catch (error) {
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(500);
    res.end(
      JSON.stringify({
        error: 'Internal server error',
        message: (error as Error).message,
      }),
    );
  }
});

server.listen(PORT, () => {
  console.log(`🚀 Hawkeye API Server listening on http://localhost:${PORT}`);
  console.log(`📝 Available endpoints:`);
  console.log(`   GET  /api/health        - Health check`);
  console.log(`   POST /api/analyze       - Analyze project`);
  console.log(`   POST /api/report        - Generate report`);
  console.log(`\n📚 Documentation: https://github.com/lucasvsantos591-hue/hawkeye`);
});

process.on('SIGTERM', () => {
  console.log('Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
