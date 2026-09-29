import type { ExposureContext, DetectedEndpoint, SSLCertificateInfo } from '../../types/context.js';
import { DNSDetector } from './dns_detector.js';
import { SSLDetector } from './ssl_detector.js';
import { HTTPProbeDetector } from './http_probe_detector.js';

export interface ExposureDetectionOptions {
  domain: string;
  verbose?: boolean;
}

export class ExposureDetectionService {
  private dnsDetector: DNSDetector;
  private sslDetector: SSLDetector;
  private httpDetector: HTTPProbeDetector;
  private verbose: boolean;

  constructor(verbose: boolean = false) {
    this.dnsDetector = new DNSDetector();
    this.sslDetector = new SSLDetector();
    this.httpDetector = new HTTPProbeDetector();
    this.verbose = verbose;
  }

  async detectExposure(options: ExposureDetectionOptions): Promise<ExposureContext> {
    const { domain, verbose } = { ...options, verbose: this.verbose };

    if (verbose) {
      console.log(`🔍 Detecting internet-facing exposure for: ${domain}`);
    }

    const timestamp = new Date().toISOString();
    const context: ExposureContext = {
      is_internet_facing: false,
      detection_methods: [],
      verified_endpoints: [],
      detection_confidence: 0,
      verification_timestamp: timestamp,
    };

    // Run all detection methods in parallel
    const [dnsResult, sslResult, httpResults] = await Promise.all([
      this.dnsDetector.lookupDomain(domain),
      this.sslDetector.detectSSL(domain),
      this.httpDetector.probeEndpoints(domain),
    ]);

    // Process DNS results
    if (dnsResult.success && dnsResult.records.length > 0) {
      context.detection_methods?.push('DNS');
      context.dns_records = {
        a_records: dnsResult.records
          .filter((r) => r.type === 'A')
          .map((r) => r.value),
        aaaa_records: dnsResult.records
          .filter((r) => r.type === 'AAAA')
          .map((r) => r.value),
        cname_records: dnsResult.records
          .filter((r) => r.type === 'CNAME')
          .map((r) => r.value),
      };

      if (verbose) {
        console.log(`  ✓ DNS lookup successful: ${dnsResult.records.length} records found`);
      }
    }

    // Process SSL results
    if (sslResult.success && sslResult.certificate) {
      context.detection_methods?.push('SSL');
      context.ssl_certificate = sslResult.certificate as SSLCertificateInfo;

      const endpoint: DetectedEndpoint = {
        url: `https://${domain}`,
        method: 'SSL',
        verified: true,
        verification_timestamp: timestamp,
      };
      context.verified_endpoints?.push(endpoint);

      if (verbose) {
        console.log(
          `  ✓ SSL certificate found: ${sslResult.certificate.subject}`,
        );
      }
    }

    // Process HTTP probe results
    if (httpResults.length > 0) {
      context.detection_methods?.push('HTTP_PROBE');
      const endpoints: DetectedEndpoint[] = httpResults
        .filter((r) => r.reachable)
        .map((r) => ({
          url: r.url,
          method: 'HTTP_PROBE',
          status_code: r.status_code,
          verified: true,
          verification_timestamp: timestamp,
        }));

      context.verified_endpoints?.push(...endpoints);

      if (verbose) {
        console.log(`  ✓ HTTP probes successful: ${endpoints.length} endpoints reached`);
      }
    }

    // Determine if internet-facing
    const hasPublicEndpoints =
      (context.dns_records?.a_records?.length || 0) > 0 ||
      (context.dns_records?.aaaa_records?.length || 0) > 0 ||
      (context.verified_endpoints?.length || 0) > 0;

    context.is_internet_facing = hasPublicEndpoints;

    // Calculate confidence score
    let confidence = 0;
    if (dnsResult.success) confidence += 30;
    if (sslResult.success) confidence += 40;
    if (httpResults.length > 0) confidence += 30;

    context.detection_confidence = Math.min(confidence, 100);
    context.verification_timestamp = timestamp;

    if (verbose) {
      console.log(
        `  📊 Detection confidence: ${context.detection_confidence}%`,
      );
      console.log(
        `  🌐 Internet-facing: ${context.is_internet_facing ? 'YES' : 'NO'}`,
      );
    }

    return context;
  }
}
