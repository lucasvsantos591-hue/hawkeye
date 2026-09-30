const USER_AGENT = 'hawkeye-cli (+https://github.com/lucasvsantos591-hue/hawkeye)';

export async function fetchText(url: string, init: { timeoutMs?: number; retries?: number } = {}): Promise<string> {
  return request(url, { ...init, parse: res => res.text() }) as Promise<string>;
}

export async function fetchJson<T>(
  url: string,
  init: { method?: string; body?: unknown; timeoutMs?: number; retries?: number } = {},
): Promise<T> {
  return request(url, { ...init, parse: res => res.json() }) as Promise<T>;
}

async function request(
  url: string,
  init: {
    method?: string;
    body?: unknown;
    timeoutMs?: number;
    retries?: number;
    parse: (res: Response) => Promise<unknown>;
  },
): Promise<unknown> {
  const { method = 'GET', body, timeoutMs = 30_000, retries = 3, parse } = init;
  let lastError: unknown;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        method,
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'application/json',
          ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.ok) return await parse(res);
      lastError = new Error(`${method} ${url} -> HTTP ${res.status}`);
      if (res.status !== 429 && res.status < 500) break;
    } catch (error) {
      lastError = error;
    }
    if (attempt < retries) await new Promise(r => setTimeout(r, 500 * 2 ** attempt));
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}
