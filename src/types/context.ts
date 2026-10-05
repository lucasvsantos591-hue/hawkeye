/**
 * Result of `hawkeye expose`: heuristic internet-exposure signals (DNS, TLS certificate, HTTP probe)
 * for one hostname.
 */

export interface SSLCertificateInfo {
  issuer?: string;
  subject?: string;
  valid_from?: string;
  valid_to?: string;
  fingerprint?: string;
  is_self_signed?: boolean;
}

export interface DetectedEndpoint {
  url: string;
  method?: 'DNS' | 'SSL' | 'WHOIS' | 'HTTP_PROBE';
  status_code?: number;
  verified?: boolean;
  verification_timestamp?: string;
}

export interface ExposureContext {
  is_internet_facing?: boolean;
  detection_methods?: Array<'DNS' | 'SSL' | 'WHOIS' | 'HTTP_PROBE' | 'SECRET_SCAN'>;
  verified_endpoints?: DetectedEndpoint[];
  ssl_certificate?: SSLCertificateInfo;
  dns_records?: {
    a_records?: string[];
    aaaa_records?: string[];
    cname_records?: string[];
  };
  cdn_info?: {
    provider?: string;
    detected?: boolean;
    verification_timestamp?: string;
  };
  secret_exposure?: {
    found?: boolean;
    secret_types?: string[];
    verification_timestamp?: string;
  };
  verification_timestamp?: string;
  detection_confidence?: number;
}
