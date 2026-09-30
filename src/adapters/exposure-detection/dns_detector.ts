import axios from 'axios';

export interface DNSRecord {
  type: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT';
  value: string;
}

export interface DNSLookupResult {
  domain: string;
  success: boolean;
  records: DNSRecord[];
  error?: string;
  timestamp: string;
}

export class DNSDetector {
  async lookupDomain(domain: string): Promise<DNSLookupResult> {
    const timestamp = new Date().toISOString();

    try {
      const records = await this.performDNSLookup(domain);
      return {
        domain,
        success: true,
        records,
        timestamp,
      };
    } catch (error) {
      return {
        domain,
        success: false,
        records: [],
        error: (error as Error).message,
        timestamp,
      };
    }
  }

  private async performDNSLookup(domain: string): Promise<DNSRecord[]> {
    const records: DNSRecord[] = [];

    try {
      const response = await axios.get('https://dns.google/resolve', {
        params: {
          name: domain,
          type: 'A',
        },
        timeout: 5000,
      });

      if (response.data.Answer) {
        for (const answer of response.data.Answer) {
          records.push({
            type: this.getRecordType(answer.type),
            value: answer.data,
          });
        }
      }

      return records;
    } catch (error) {
      throw new Error(`DNS lookup failed for ${domain}: ${(error as Error).message}`);
    }
  }

  private getRecordType(typeId: number): 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' {
    const typeMap: Record<number, 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT'> = {
      1: 'A',
      28: 'AAAA',
      5: 'CNAME',
      15: 'MX',
      16: 'TXT',
    };
    return typeMap[typeId] || 'A';
  }
}
