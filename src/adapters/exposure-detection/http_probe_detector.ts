import axios, { AxiosError } from 'axios';

export interface HTTPProbeResult {
  url: string;
  reachable: boolean;
  status_code?: number;
  response_time_ms?: number;
  error?: string;
  timestamp: string;
}

export class HTTPProbeDetector {
  private readonly commonEndpoints = [
    '',
    '/api',
    '/health',
    '/api/health',
    '/api/status',
    '/.well-known/security.txt',
  ];

  async probeEndpoints(domain: string): Promise<HTTPProbeResult[]> {
    const results: HTTPProbeResult[] = [];

    const baseUrls = [
      `https://${domain}`,
      `https://api.${domain}`,
      `https://www.${domain}`,
    ];

    for (const baseUrl of baseUrls) {
      for (const endpoint of this.commonEndpoints) {
        const url = baseUrl + endpoint;
        const result = await this.probeUrl(url);
        if (result.reachable) {
          results.push(result);
        }
      }
    }

    return results;
  }

  private async probeUrl(url: string): Promise<HTTPProbeResult> {
    const timestamp = new Date().toISOString();
    const startTime = Date.now();

    try {
      const response = await axios.head(url, {
        timeout: 5000,
        validateStatus: () => true,
      });

      const responseTimetMs = Date.now() - startTime;

      return {
        url,
        reachable: response.status < 400,
        status_code: response.status,
        response_time_ms: responseTimetMs,
        timestamp,
      };
    } catch (error) {
      if ((error as AxiosError).code === 'ENOTFOUND') {
        return {
          url,
          reachable: false,
          error: 'Domain not found',
          timestamp,
        };
      }

      return {
        url,
        reachable: false,
        error: (error as Error).message,
        timestamp,
      };
    }
  }
}
