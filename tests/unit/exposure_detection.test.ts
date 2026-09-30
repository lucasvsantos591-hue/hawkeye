import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import {
  ExposureDetectionService,
  DNSDetector,
  SSLDetector,
  HTTPProbeDetector,
} from '../../src/adapters/exposure-detection/index.js';

vi.mock('axios');
const mockedAxios = axios as any;

describe('ExposureDetectionService', () => {
  let service: ExposureDetectionService;

  beforeEach(() => {
    service = new ExposureDetectionService(false);
    vi.clearAllMocks();
  });

  describe('ExposureDetectionService.detectExposure', () => {
    it('should detect internet-facing applications with DNS records', async () => {
      mockedAxios.get.mockResolvedValue({
        data: {
          Answer: [
            { type: 1, data: '93.184.216.34' },
            { type: 28, data: '2606:2800:220:1:248:1893:25c8:1946' },
          ],
        },
      });

      const result = await service.detectExposure({
        domain: 'example.com',
      });

      expect(result.is_internet_facing).toBe(true);
      expect(result.detection_methods).toContain('DNS');
      expect(result.dns_records?.a_records).toContain('93.184.216.34');
      expect(result.dns_records?.aaaa_records).toContain(
        '2606:2800:220:1:248:1893:25c8:1946',
      );
    });

    it('should handle DNS lookup failures gracefully', async () => {
      mockedAxios.get.mockRejectedValue(new Error('DNS lookup failed'));

      const result = await service.detectExposure({
        domain: 'nonexistent-domain-12345.com',
      });

      expect(result.detection_confidence).toBeLessThan(100);
      expect(result.dns_records).toBeUndefined();
    });

    it('should calculate confidence score correctly', async () => {
      mockedAxios.get
        .mockResolvedValueOnce({
          data: {
            Answer: [{ type: 1, data: '93.184.216.34' }],
          },
        })
        .mockResolvedValueOnce({
          data: [
            {
              issuer_name: "Let's Encrypt",
              common_name: 'example.com',
              not_before: '2026-01-15T00:00:00Z',
              not_after: '2027-04-15T23:59:59Z',
            },
          ],
        })
        .mockResolvedValue({ status: 200 });

      const result = await service.detectExposure({
        domain: 'example.com',
      });

      // Confidence should be combination of successful detections
      expect(result.detection_confidence).toBeGreaterThan(0);
      expect(result.detection_confidence).toBeLessThanOrEqual(100);
    });

    it('should identify non-internet-facing applications', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Network error'));

      const result = await service.detectExposure({
        domain: 'internal-app.local',
      });

      expect(result.is_internet_facing).toBe(false);
      expect(result.verified_endpoints?.length || 0).toBe(0);
    });
  });

  describe('DNSDetector', () => {
    let dnsDetector: DNSDetector;

    beforeEach(() => {
      dnsDetector = new DNSDetector();
    });

    it('should lookup A and AAAA records', async () => {
      mockedAxios.get.mockResolvedValue({
        data: {
          Answer: [
            { type: 1, data: '192.0.2.1' },
            { type: 28, data: '2001:db8::1' },
          ],
        },
      });

      const result = await dnsDetector.lookupDomain('example.com');

      expect(result.success).toBe(true);
      expect(result.records).toHaveLength(2);
      expect(result.records[0]).toEqual({ type: 'A', value: '192.0.2.1' });
      expect(result.records[1]).toEqual({ type: 'AAAA', value: '2001:db8::1' });
    });

    it('should handle DNS lookup timeouts', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Timeout'));

      const result = await dnsDetector.lookupDomain('slow-domain.com');

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should return empty records for no DNS answers', async () => {
      mockedAxios.get.mockResolvedValue({
        data: {},
      });

      const result = await dnsDetector.lookupDomain('nodns.example.com');

      expect(result.success).toBe(true);
      expect(result.records).toHaveLength(0);
    });
  });

  describe('SSLDetector', () => {
    let sslDetector: SSLDetector;

    beforeEach(() => {
      sslDetector = new SSLDetector();
    });

    it('should detect valid SSL certificates', async () => {
      mockedAxios.get.mockResolvedValue({
        data: [
          {
            issuer_name: "Let's Encrypt",
            common_name: 'example.com',
            not_before: '2026-01-15T00:00:00Z',
            not_after: '2027-04-15T23:59:59Z',
          },
        ],
      });

      const result = await sslDetector.detectSSL('example.com');

      expect(result.success).toBe(true);
      expect(result.certificate).toBeDefined();
      expect(result.certificate?.subject).toBe('example.com');
      expect(result.certificate?.issuer).toBe("Let's Encrypt");
      expect(result.certificate?.is_self_signed).toBe(false);
    });

    it('should detect self-signed certificates', async () => {
      mockedAxios.get.mockResolvedValue({
        data: [
          {
            issuer_name: 'example.com',
            common_name: 'example.com',
            not_before: '2026-01-15T00:00:00Z',
            not_after: '2027-04-15T23:59:59Z',
          },
        ],
      });

      const result = await sslDetector.detectSSL('example.com');

      expect(result.certificate?.is_self_signed).toBe(true);
    });

    it('should handle SSL detection failures', async () => {
      mockedAxios.get.mockRejectedValue(new Error('No certificate found'));

      const result = await sslDetector.detectSSL('nocert.example.com');

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('HTTPProbeDetector', () => {
    let httpDetector: HTTPProbeDetector;

    beforeEach(() => {
      httpDetector = new HTTPProbeDetector();
    });

    it('should probe common endpoints', async () => {
      mockedAxios.head.mockResolvedValue({
        status: 200,
      });

      const results = await httpDetector.probeEndpoints('example.com');

      expect(results.length).toBeGreaterThan(0);
      expect(results[0].reachable).toBe(true);
      expect(results[0].status_code).toBe(200);
    });

    it('should handle unreachable endpoints', async () => {
      mockedAxios.head.mockRejectedValue(new Error('Connection refused'));

      const results = await httpDetector.probeEndpoints('offline-host.local');

      expect(results.every((r) => !r.reachable)).toBe(true);
    });

    it('should handle DNS resolution failures', async () => {
      mockedAxios.head.mockRejectedValue({
        code: 'ENOTFOUND',
      });

      const results = await httpDetector.probeEndpoints('nonexistent.invalid');

      expect(results).toEqual([]);
    });

    it('should measure response time', async () => {
      const start = Date.now();
      mockedAxios.head.mockResolvedValue({ status: 200 });

      const results = await httpDetector.probeEndpoints('fast-host.local');

      expect(results[0].response_time_ms).toBeDefined();
      expect(results[0].response_time_ms).toBeLessThanOrEqual(
        Date.now() - start + 100,
      );
    });
  });

  describe('Integration scenarios', () => {
    it('should handle completely offline domain', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Network error'));
      mockedAxios.head.mockRejectedValue(new Error('Network error'));

      const result = await service.detectExposure({
        domain: 'completely-offline.local',
      });

      expect(result.is_internet_facing).toBe(false);
      expect(result.detection_confidence).toBeLessThanOrEqual(0);
    });

    it('should handle mixed results (DNS works, SSL fails)', async () => {
      mockedAxios.get
        .mockResolvedValueOnce({
          data: { Answer: [{ type: 1, data: '192.0.2.1' }] },
        })
        .mockRejectedValueOnce(new Error('SSL error'));

      mockedAxios.head.mockRejectedValue(new Error('Connection refused'));

      const result = await service.detectExposure({
        domain: 'partial-exposure.com',
      });

      expect(result.is_internet_facing).toBe(true);
      expect(result.detection_methods).toContain('DNS');
      expect(result.detection_confidence).toBeGreaterThan(0);
    });
  });
});
