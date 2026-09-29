import { Argv } from 'yargs';
import * as fs from 'fs';
import * as dns from 'dns/promises';
import * as https from 'https';
import type { ExposureContext } from '../../types/context.js';

export interface ExposeOptions {
  hostname?: string;
  port?: number;
  output?: string;
  detectMethods?: string[];
}

/**
 * Detect if an application is internet-facing
 * Checks: DNS records, SSL certificates, public IPs, CDN detection
 */
async function checkInternetExposure(hostname: string): Promise<ExposureContext> {
  const exposureContext: ExposureContext = {
    is_internet_facing: false,
    detection_confidence: 0,
    detection_methods: [],
    verified_endpoints: [],
  };

  try {
    // 1. DNS Resolution
    console.log(`🔍 Checking DNS records for ${hostname}...`);
    try {
      const aRecords = await dns.resolve4(hostname);
      exposureContext.dns_records = {
        a_records: aRecords,
      };

      // Check if it's a public IP (not localhost or private)
      const isPublicIP = aRecords.some(ip => !isPrivateIP(ip));
      if (isPublicIP) {
        exposureContext.is_internet_facing = true;
        exposureContext.detection_methods?.push('DNS');
        exposureContext.detection_confidence = Math.min(100, (exposureContext.detection_confidence || 0) + 40);
      }
    } catch (e) {
      // DNS resolution failed, might be local-only
    }

    // 2. SSL Certificate Check
    console.log(`🔐 Checking SSL certificate for ${hostname}...`);
    try {
      const cert = await getCertificate(hostname);
      if (cert) {
        exposureContext.ssl_certificate = cert;
        exposureContext.is_internet_facing = true;
        exposureContext.detection_methods?.push('SSL');
        exposureContext.detection_confidence = Math.min(100, (exposureContext.detection_confidence || 0) + 50);
      }
    } catch (e) {
      // No HTTPS, might still be HTTP
    }

    // 3. HTTP Endpoint Check
    console.log(`🌐 Checking HTTP endpoints for ${hostname}...`);
    try {
      const endpoints = await checkEndpoints(hostname);
      if (endpoints.length > 0) {
        exposureContext.verified_endpoints = endpoints;
        exposureContext.is_internet_facing = true;
        exposureContext.detection_methods?.push('HTTP_PROBE');
        exposureContext.detection_confidence = Math.min(100, (exposureContext.detection_confidence || 0) + 45);
      }
    } catch (e) {
      // Endpoint not accessible
    }

    // 4. CDN Detection (simplified)
    console.log(`☁️ Checking for CDN providers...`);
    const cdnInfo = detectCDN(exposureContext.dns_records?.a_records || []);
    if (cdnInfo.detected) {
      exposureContext.cdn_info = cdnInfo;
      exposureContext.detection_methods?.push('DNS');
    }

    exposureContext.detection_confidence = Math.min(100, exposureContext.detection_confidence || 0);
    exposureContext.verification_timestamp = new Date().toISOString();

    console.log(`✅ Internet-facing: ${exposureContext.is_internet_facing ? 'YES ⚠️' : 'NO ✓'}`);
    console.log(`📊 Confidence: ${exposureContext.detection_confidence}%`);

  } catch (error) {
    console.error(`Error during exposure detection: ${(error as Error).message}`);
  }

  return exposureContext;
}

function isPrivateIP(ip: string): boolean {
  const privateRanges = [
    /^127\./,           // 127.0.0.0/8
    /^10\./,             // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16.0.0/12
    /^192\.168\./,       // 192.168.0.0/16
    /^localhost$/i,
  ];
  return privateRanges.some(range => range.test(ip));
}

async function getCertificate(hostname: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const options = {
      hostname,
      port: 443,
      rejectUnauthorized: false,
      method: 'HEAD',
      timeout: 5000,
    };

    const req = https.request(options, (res) => {
      const cert = (res.socket as any).getPeerCertificate();
      if (cert && cert.subject) {
        resolve({
          subject: cert.subject?.CN || cert.subject?.O || 'Unknown',
          issuer: cert.issuer?.CN || cert.issuer?.O || 'Unknown',
          valid_from: new Date(cert.valid_from).toISOString(),
          valid_to: new Date(cert.valid_to).toISOString(),
          is_self_signed: cert.issuer?.CN === cert.subject?.CN,
        });
      } else {
        resolve(null);
      }
      req.destroy();
    });

    req.on('error', () => reject(new Error('No certificate')));
    req.setTimeout(5000, () => req.destroy());
    req.end();
  });
}

async function checkEndpoints(hostname: string): Promise<any[]> {
  const endpoints = [];
  const urls = [
    { url: `http://${hostname}`, method: 'GET' },
    { url: `https://${hostname}`, method: 'GET' },
    { url: `http://${hostname}:8080`, method: 'GET' },
  ];

  for (const endpoint of urls) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(endpoint.url, {
        method: endpoint.method,
        signal: controller.signal,
      }).catch(() => null);

      clearTimeout(timeoutId);

      if (response && response.status < 500) {
        endpoints.push({
          url: endpoint.url,
          method: endpoint.method,
          status_code: response.status,
        });
      }
    } catch (e) {
      // Endpoint not accessible
    }
  }

  return endpoints;
}

function detectCDN(ips: string[]): { detected: boolean; provider?: string } {
  const cdnPatterns: { [key: string]: RegExp[] } = {
    'Cloudflare': [/^104\.(16|24|28|31|32|33|34|36|37|39|40|41|42|43|44|45|51|56|57|58|59|60|61|62|63|64|65|66|67|68|69|70|71|72|73|74|75|76|77|78|79|80|81|82|83|84|85|86|87|88|89|90|91|92|93|94|95|96|97|98|99|100|101|102|103|104|105|106|107|108|109|110|111|112|113|114|115|116|117|118|119|120|121|122|123|124|125|126|127|128|129|130|131|132|133|134|135|136|137|138|139|140|141|142|143|144|145|146|147|148|149|150|151|152|153|154|155|156|157|158|159|160|161|162|163|164|165|166|167|168|169|170|171|172|173|174|175|176|177|178|179|180|181|182|183|184|185|186|187|188|189|190|191|192|193|194|195|196|197|198|199|200|201|202|203|204|205|206|207|208|209|210|211|212|213|214|215|216|217|218|219|220|221|222|223|224|225|226|227|228|229|230|231|232|233|234|235|236|237|238|239|240|241|242|243|244|245|246|247|248|249|250|251|252|253|254|255)\./, /^162\.125\./],
    'Akamai': [/^23\./, /^184\.50\./],
    'AWS CloudFront': [/^99\./],
  };

  for (const [provider, patterns] of Object.entries(cdnPatterns)) {
    if (ips.some(ip => patterns.some(pattern => pattern.test(ip)))) {
      return { detected: true, provider };
    }
  }

  return { detected: false };
}

export async function runExposureCheck(opts: ExposeOptions): Promise<ExposureContext> {
  if (!opts.hostname) {
    throw new Error('Hostname is required for exposure check');
  }

  const exposure = await checkInternetExposure(opts.hostname);

  if (opts.output) {
    fs.writeFileSync(opts.output, JSON.stringify(exposure, null, 2));
    console.log(`✅ Exposure context saved to: ${opts.output}`);
  }

  return exposure;
}

export const exposeCommand = {
  command: 'expose <hostname>',
  description: 'Check if application is internet-facing (DNS, SSL, HTTP)',

  builder: (yargs: Argv) => {
    return yargs
      .positional('hostname', {
        describe: 'Hostname or domain to check',
        type: 'string',
      })
      .option('port', {
        type: 'number',
        description: 'Port number (default: 80/443)',
      })
      .option('output', {
        alias: 'o',
        type: 'string',
        description: 'Output file path for exposure context JSON',
      });
  },

  handler: async (argv: any) => {
    const options: ExposeOptions = {
      hostname: argv.hostname,
      port: argv.port,
      output: argv.output,
    };

    try {
      console.log(`\n🔎 Checking if ${options.hostname} is internet-facing...\n`);
      await runExposureCheck(options);
    } catch (error) {
      console.error('❌ Exposure check failed:', (error as Error).message);
      process.exit(1);
    }
  },
};
