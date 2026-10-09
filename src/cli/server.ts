#!/usr/bin/env node

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID, timingSafeEqual } from 'crypto';
import { AnalysisEngine, AnalysisInputError, TOOL_VERSION } from '../core/analysis_engine.js';
import { HTMLReportRenderer } from '../adapters/report/html_renderer.js';
import { SARIFRenderer } from '../adapters/report/sarif_renderer.js';
import { ContextLoader } from '../adapters/context/context_loader.js';
import { assertAnalysisResult } from '../types/analysis-result.js';

const MAX_BODY = 5 * 1024 * 1024;
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]', 'localhost']);

export interface ServerConfig {
  /** Bearer token; empty means no auth, which is only allowed on loopback. */
  token: string;
  /** Real path of the directory every projectPath must stay inside. */
  allowedRoot: string;
  corsOrigin?: string;
  maxConcurrent?: number;
  /** Running mvn/gradle executes the analyzed project's build scripts, so it is opt-in for the API. */
  allowBuildTools?: boolean;
}

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function send(res: http.ServerResponse, status: number, body: unknown, type = 'application/json') {
  res.writeHead(status, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

/** The Host header without its port ("[::1]:3000" -> "[::1]"). */
function hostName(header: string | undefined): string {
  const host = (header ?? '').toLowerCase();
  return host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.replace(/:\d+$/, '');
}

async function readBody(req: http.IncomingMessage): Promise<any> {
  // Browsers send text/plain and form posts cross-site without a CORS preflight; JSON forces one.
  const type = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/json') throw new HttpError(415, 'Content-Type must be application/json');
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

export function createServer(config: ServerConfig): http.Server {
  const { token, allowedRoot, corsOrigin = '', maxConcurrent = 2, allowBuildTools = false } = config;
  const startTime = Date.now();
  let running = 0;

  const authorized = (req: http.IncomingMessage): boolean => {
    if (!token) return true;
    const header = req.headers.authorization ?? '';
    const given = Buffer.from(header.startsWith('Bearer ') ? header.slice(7) : '');
    const expected = Buffer.from(token);
    return given.length === expected.length && timingSafeEqual(given, expected);
  };

  const resolveProjectPath = (input: unknown): string => {
    if (typeof input !== 'string' || !input) throw new HttpError(400, 'projectPath is required');
    let real: string;
    try {
      real = fs.realpathSync(path.resolve(allowedRoot, input));
    } catch {
      throw new HttpError(400, 'projectPath not found');
    }
    if (real !== allowedRoot && !real.startsWith(allowedRoot + path.sep)) {
      throw new HttpError(403, 'projectPath is outside HAWKEYE_ALLOWED_ROOT');
    }
    return real;
  };

  return http.createServer(async (req, res) => {
    const pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
    const method = req.method ?? 'GET';

    // Without a token the API trusts anything that reaches it on loopback. A web page can reach it too
    // (DNS rebinding: evil.example resolving to 127.0.0.1), and then its Host header is not a loopback name.
    if (!token && !LOOPBACK_HOSTS.has(hostName(req.headers.host))) {
      return send(res, 421, { error: 'Host must be localhost when HAWKEYE_API_TOKEN is not set' });
    }

    if (corsOrigin) {
      res.setHeader('Access-Control-Allow-Origin', corsOrigin);
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
        if (running >= maxConcurrent) throw new HttpError(429, 'Too many analyses in progress, retry later');
        running++;
        try {
          const result = await new AnalysisEngine({
            projectPath,
            level,
            includeDev: data.includeDev === true,
            allowBuildTool: allowBuildTools,
          }).analyze();
          const format = data.format ?? 'json';
          if (format === 'sarif') return send(res, 200, new SARIFRenderer(result).render());
          if (format === 'html') {
            const html = new HTMLReportRenderer(result, ContextLoader.forReport(projectPath).context).render();
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
        const projectDir = data.projectPath ? resolveProjectPath(data.projectPath) : null;
        const { context } = ContextLoader.forReport(projectDir, result.context?.exposure);
        if (data.format === 'sarif') return send(res, 200, new SARIFRenderer(result).render());
        if (data.format === 'json') return send(res, 200, result);
        return send(res, 200, new HTMLReportRenderer(result, context).render(), 'text/html; charset=utf-8');
      }

      throw new HttpError(404, 'Not found');
    } catch (error) {
      if (error instanceof HttpError) return send(res, error.status, { error: error.message });
      if (error instanceof AnalysisInputError) return send(res, 422, { error: error.message });
      const requestId = randomUUID();
      process.stderr.write(`[${new Date().toISOString()}] ${requestId} ${method} ${pathname} failed: ${(error as Error).stack}\n`);
      return send(res, 500, { error: 'Internal error', requestId });
    }
  });
}

function main() {
  const port = Number(process.env.HAWKEYE_PORT ?? 3000);
  const host = process.env.HAWKEYE_HOST ?? '127.0.0.1';
  const token = process.env.HAWKEYE_API_TOKEN ?? '';
  const allowedRoot = fs.realpathSync(process.env.HAWKEYE_ALLOWED_ROOT ?? process.cwd());

  if (!LOOPBACK.has(host) && !token) {
    process.stderr.write(`Refusing to listen on ${host} without HAWKEYE_API_TOKEN set.\n`);
    process.exit(1);
  }

  const server = createServer({
    token,
    allowedRoot,
    corsOrigin: process.env.HAWKEYE_CORS_ORIGIN ?? '',
    maxConcurrent: Number(process.env.HAWKEYE_MAX_CONCURRENCY ?? 2),
    allowBuildTools: process.env.HAWKEYE_ALLOW_BUILD_TOOLS === '1',
  });
  server.requestTimeout = 10 * 60 * 1000;
  server.listen(port, host, () => {
    process.stderr.write(
      `Hawkeye API ${TOOL_VERSION} on http://${host}:${port} (root: ${allowedRoot}, auth: ${token ? 'token' : 'none, loopback only'})\n`,
    );
  });

  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.on(signal, () => server.close(() => process.exit(0)));
  }
}

const invokedPath = process.argv[1] ? fs.realpathSync(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) main();
