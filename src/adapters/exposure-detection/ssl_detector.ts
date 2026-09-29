import axios from 'axios';

export interface SSLDetectionResult {
  domain: string;
  success: boolean;
  certificate?: {
    issuer: string;
    subject: string;
    valid_from: string;
    valid_to: string;
    fingerprint?: string;
    is_self_signed: boolean;
  };
  error?: string;
  timestamp: string;
}

export class SSLDetector {
  async detectSSL(domain: string): Promise<SSLDetectionResult> {
    const timestamp = new Date().toISOString();

    try {
      const certInfo = await this.fetchCertificate(domain);
      return {
        domain,
        success: true,
        certificate: certInfo,
        timestamp,
      };
    } catch (error) {
      return {
        domain,
        success: false,
        error: (error as Error).message,
        timestamp,
      };
    }
  }

  private async fetchCertificate(
    domain: string,
  ): Promise<SSLDetectionResult['certificate']> {
    try {
      const response = await axios.get(
        `https://api.crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
        {
          timeout: 5000,
          headers: {
            'User-Agent': 'Hawkeye/1.0',
          },
        },
      );

      if (Array.isArray(response.data) && response.data.length > 0) {
        const cert = response.data[0];
        return {
          issuer: cert.issuer_name || 'Unknown',
          subject: cert.common_name || domain,
          valid_from: cert.not_before || new Date().toISOString(),
          valid_to: cert.not_after || new Date().toISOString(),
          is_self_signed: this.checkSelfSigned(cert),
        };
      }

      throw new Error(`No certificate found for ${domain}`);
    } catch (error) {
      throw new Error(
        `SSL detection failed for ${domain}: ${(error as Error).message}`,
      );
    }
  }

  private checkSelfSigned(cert: any): boolean {
    return cert.issuer_name === cert.common_name;
  }
}
