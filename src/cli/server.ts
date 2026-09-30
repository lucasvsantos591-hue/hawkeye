#!/usr/bin/env node

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { timingSafeEqual } from 'crypto';
import { AnalysisEngine, TOOL_VERSION } from '../core/analysis_engine.js';
import { HTMLReportRenderer } from '../adapters/report/html_renderer.js';
import { SARIFRenderer } from '../adapters/report/sarif_renderer.js';
import { ContextLoader } from '../adapters/context/context_loader.js';
import { assertAnalysisResult } from '../types/analysis-result.js';

const PORT = Number(process.env.HAWKEYE_PORT ?? 3000);
const HOST = process.env.HAWKEYE_HOST ?? '127.0.0.1';
const TOKEN = process.env.HAWKEYE_API_TOKEN ?? '';
const ALLOWED_ROOT = fs.realpathSync(process.env.HAWKEYE_ALLOWED_ROOT ?? process.cwd());
const CORS_ORIGIN = process.env.HAWKEYE_CORS_ORIGIN ?? '';
const MAX_BODY = 5 * 1024 * 1024;
const MAX_CONCURRENT = Number(process.env.HAWKEYE_MAX_CONCURRENCY ?? 2);
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);
// Running mvn/gradle executes the analyzed project's build scripts, so it is opt-in for the API.
const ALLOW_BUILD_TOOLS = process.env.HAWKEYE_ALLOW_BUILD_TOOLS === '1';

if (!LOOPBACK.has(HOST) && !TOKEN) {
  process.stderr.write(`Refusing to listen on ${HOST} without HAWKEYE_API_TOKEN set.\n`);
  process.exit(1);
}

const startTime = Date.now();
let running = 0;

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function send(res: http.ServerResponse, status: number, body: unknown, type = 'application/json') {
  res.writeHead(status, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

function authorized(req: http.IncomingMessage): boolean {
  if (!TOKEN) return true;
  const header = req.headers.authorization ?? '';
  const given = Buffer.from(header.startsWith('Bearer ') ? header.slice(7) : '');
  const expected = Buffer.from(TOKEN);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

async function readBody(req: http.IncomingMessage): Promise<any> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, 'Request body too large');
    chunks.push(chunk as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf-8') || '{}');
  } catch {
    throw new HttpError(400, 'Body must be valid JSON');
  }
}

function resolveProjectPath(input: unknown): string {
  if (typeof input !== 'string' || !input) throw new HttpError(400, 'projectPath is required');
  let real: string;
  try {
    real = fs.realpathSync(path.resolve(ALLOWED_ROOT, input));
  } catch {
    throw new HttpError(400, 'projectPath not found');
  }
  if (real !== ALLOWED_ROOT && !real.startsWith(ALLOWED_ROOT + path.sep)) {
    throw new HttpError(403, 'projectPath is outside HAWKEYE_ALLOWED_ROOT');
  }
  return real;
}

const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
  const method = req.method ?? 'GET';

  if (CORS_ORIGIN) {
    res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (method === 'OPTIONS') return send(res, 204, '');
  }

  try {
    if (pathname === '/api/health' && method === 'GET') {
      return send(res, 200, {
        status: 'ok',
        version: TOOL_VERSION,
        uptime: Math.floor((Date.now() - startTime) / 1000),
        busy: running,
      });
    }

    if (!authorized(req)) throw new HttpError(401, 'Missing or invalid bearer token');

    if (pathname === '/api/analyze' && method === 'POST') {
      const data = await readBody(req);
      const projectPath = resolveProjectPath(data.projectPath);
      const level = [1, 2, 3].includes(data.level) ? data.level : 2;
      if (running >= MAX_CONCURRENT) throw new HttpError(429, 'Too many analyses in progress, retry later');
      running++;
      try {
        const result = await new AnalysisEngine({
          projectPath,
          level,
          includeDev: data.includeDev === true,
          allowBuildTool: ALLOW_BUILD_TOOLS,
        }).analyze();
        const format = data.format ?? 'json';
        if (format === 'sarif') return send(res, 200, new SARIFRenderer(result).render());
        if (format === 'html') {
          const html = new HTMLReportRenderer(result, ContextLoader.loadContext(projectPath)).render();
          return send(res, 200, html, 'text/html; charset=utf-8');
        }
        return send(res, 200, result);
      } finally {
        running--;
      }
    }

    if (pathname === '/api/report' && method === 'POST') {
      const data = await readBody(req);
      let result;
      try {
        result = assertAnalysisResult(data.analysisResult);
      } catch (error) {
        throw new HttpError(400, `Invalid analysisResult: ${(error as Error).message}`);
      }
      const context = data.projectPath ? ContextLoader.loadContext(resolveProjectPath(data.projectPath)) : null;
      if (data.format === 'sarif') return send(res, 200, new SARIFRenderer(result).render());
      if (data.format === 'json') return send(res, 200, result);
      return send(res, 200, new HTMLReportRenderer(result, context).render(), 'text/html; charset=utf-8');
    }

    throw new HttpError(404, 'Not found');
  } catch (error) {
    if (error instanceof HttpError) return send(res, error.status, { error: error.message });
    process.stderr.write(`[${new Date().toISOString()}] ${method} ${pathname} failed: ${(error as Error).stack}\n`);
    return send(res, 500, { error: 'Analysis failed', detail: (error as Error).message });
  }
});

server.requestTimeout = 10 * 60 * 1000;
server.listen(PORT, HOST, () => {
  process.stderr.write(
    `Hawkeye API ${TOOL_VERSION} on http://${HOST}:${PORT} (root: ${ALLOWED_ROOT}, auth: ${TOKEN ? 'token' : 'none, loopback only'})\n`,
  );
});

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
