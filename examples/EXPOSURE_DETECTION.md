# Internet-Facing Exposure Detection

Hawkeye v2.2 introduces automatic detection of internet-facing applications through multiple verification methods. This guide explains how to use and interpret exposure detection results.

## Overview

Internet-facing exposure detection helps security teams understand whether their applications are publicly accessible. This context is crucial for:

- **Severity Rescoring**: CVEs in internal-only applications receive reduced severity
- **Attack Surface Understanding**: Know which endpoints are reachable from the internet
- **Risk Prioritization**: Focus remediation on publicly exposed vulnerabilities

## Quick Start

### Basic Usage

```bash
# Analyze a project with exposure detection
hawkeye analyze . --detect-exposure --context hawkeye-context.json --output report.html
```

### With Custom Domain

If your project name doesn't match your domain, provide it in the context file:

```json
{
  "application": {
    "name": "my-api",
    "description": "API service",
    "internet_facing": true
  }
}
```

Then run:

```bash
hawkeye analyze . --detect-exposure --context hawkeye-context.json
```

## Detection Methods

Hawkeye uses multiple complementary detection methods:

### 1. **DNS Resolution**
- Performs DNS A, AAAA, and CNAME lookups
- Detects if domains resolve to public IP addresses
- Confidence: High

### 2. **SSL Certificate Analysis**
- Fetches SSL certificate information from Certificate Transparency logs
- Verifies certificate validity period
- Detects self-signed certificates
- Confidence: High

### 3. **HTTP Probes**
- Attempts to reach common endpoints (root, /api, /health, etc.)
- Checks HTTP status codes
- Measures response times
- Confidence: Very High (direct reachability proof)

### 4. **CDN Detection**
- Identifies CDN providers (Cloudflare, Akamai, AWS CloudFront, etc.)
- Indicates additional network protection
- Affects severity rescoring

## Understanding Results

### Output Structure

```json
{
  "exposure": {
    "is_internet_facing": true,
    "detection_confidence": 92,
    "detection_methods": ["DNS", "SSL", "HTTP_PROBE"],
    "verified_endpoints": [
      {
        "url": "https://api.example.com",
        "method": "DNS",
        "status_code": 200,
        "verified": true,
        "verification_timestamp": "2026-09-28T10:30:00Z"
      }
    ],
    "dns_records": {
      "a_records": ["93.184.216.34"],
      "aaaa_records": ["2606:2800:220:1:248:1893:25c8:1946"]
    },
    "ssl_certificate": {
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt Authority X3",
      "valid_from": "2026-01-15T00:00:00Z",
      "valid_to": "2027-04-15T23:59:59Z",
      "is_self_signed": false
    },
    "verification_timestamp": "2026-09-28T10:31:30Z"
  }
}
```

### Confidence Scoring

The confidence score (0-100) is calculated as:

- **DNS Resolution (30%)**: Successfully resolved to IP
- **SSL Certificate (40%)**: Valid certificate found in logs
- **HTTP Probe (30%)**: Endpoint actively responding to requests

Example:
- All 3 methods successful = 100% confidence
- Only DNS succeeds = 30% confidence
- No methods succeed = 0% confidence

## Severity Rescoring

Exposure status affects CVE severity scoring:

### Internet-Facing Application

- **Original Score**: CRITICAL HIGH MEDIUM LOW
- **Rescored**: Same or adjusted based on protections
- Factor in CDN providers, WAF, SSL status

### Internal-Only Application

- **Original Score**: CRITICAL HIGH MEDIUM LOW
- **Rescored**: Reduced by 1 level
  - CRITICAL → HIGH
  - HIGH → MEDIUM
  - MEDIUM → LOW
  - LOW → LOW

Example:
```
CVE-2023-12345 in express (HIGH severity)
- Application is NOT internet-facing
- Rescored to: MEDIUM
- Reasoning: Application is not internet-facing. Reduced from HIGH to MEDIUM.
```

## Context File Configuration

### Minimal Configuration

```json
{
  "application": {
    "name": "my-api"
  }
}
```

### Full Configuration with Exposure Data

```json
{
  "application": {
    "name": "my-api",
    "description": "Production API service",
    "internet_facing": true,
    "environment": "production"
  },
  "exposure": {
    "is_internet_facing": true,
    "detection_methods": ["DNS", "SSL", "HTTP_PROBE"],
    "verified_endpoints": [
      {
        "url": "https://api.example.com",
        "method": "DNS",
        "status_code": 200,
        "verified": true,
        "verification_timestamp": "2026-09-28T10:30:00Z"
      }
    ],
    "ssl_certificate": {
      "subject": "CN=api.example.com",
      "issuer": "CN=Let's Encrypt Authority X3",
      "valid_from": "2026-01-15T00:00:00Z",
      "valid_to": "2027-04-15T23:59:59Z",
      "is_self_signed": false
    },
    "dns_records": {
      "a_records": ["93.184.216.34"]
    },
    "cdn_info": {
      "provider": "Cloudflare",
      "detected": true
    },
    "detection_confidence": 92
  }
}
```

## Report Output

### HTML Reports

The HTML report includes an **Exposure Analysis** section with:

- Internet-facing status (with visual indicator)
- Detection confidence bar
- Detection methods used
- Verified endpoints table
- DNS records
- SSL certificate information
- CDN provider details
- Verification timestamp

### DOCX Reports

The DOCX report includes a dedicated **Análise de Exposição à Internet** section with:

- Exposure status clearly marked
- Detection confidence percentage
- Detailed tables for DNS records, SSL certs, verified endpoints
- CDN provider information
- Verification audit trail

## Practical Examples

### Example 1: Detecting a Public SPA

```bash
hawkeye analyze ./frontend --detect-exposure --context context.json
```

**Results:**
- DNS lookup finds A record pointing to CloudFront
- SSL certificate detected from Let's Encrypt
- HTTP probe to root endpoint (/) returns 200
- Confidence: 100%
- Verdict: Internet-facing
- HIGH severity CVEs remain HIGH

### Example 2: Internal Microservice

```bash
hawkeye analyze ./internal-service --detect-exposure --context context.json
```

**Results:**
- DNS lookup fails or returns internal IP (10.x.x.x)
- SSL certificate lookup fails
- HTTP probes timeout or return 403
- Confidence: 0-30%
- Verdict: Internal only
- HIGH severity CVEs rescored to MEDIUM

### Example 3: Behind API Gateway with WAF

```bash
hawkeye analyze ./api --detect-exposure --context context.json
```

**Results:**
- DNS lookup finds CloudFront CNAME
- SSL certificate from AWS
- HTTP probes to /api/health return 403 (WAF blocking)
- CDN provider: AWS CloudFront detected
- Confidence: 80% (DNS + SSL positive, HTTP blocked by WAF)
- Verdict: Internet-facing with protections
- Severity adjusted down 1 level due to CDN + WAF

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Analysis with Exposure Detection

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm install -g hawkeye-cli

      - name: Run Hawkeye with Exposure Detection
        run: |
          hawkeye analyze . \
            --detect-exposure \
            --context .hawkeye/context.json \
            --output security-report.html \
            --format html
        env:
          CI: true

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.html
```

### GitLab CI

```yaml
security_scan:
  image: node:18
  script:
    - npm install -g hawkeye-cli
    - hawkeye analyze . --detect-exposure --context .hawkeye/context.json --output report.html
  artifacts:
    paths:
      - report.html
    expire_in: 30 days
```

## Troubleshooting

### Detection Returns 0% Confidence

**Causes:**
- Domain not resolvable (DNS fails)
- No SSL certificate found
- Application not listening on public endpoints

**Solutions:**
- Verify domain name is correct in context
- Check network connectivity
- Ensure application is actually running
- For internal apps, this is expected behavior

### False Positives (Reports Exposed When Not)

**Causes:**
- Domain used in development/staging
- DNS records pointing to old endpoints
- Public DNS but behind corporate firewall

**Solutions:**
- Use production domain in context
- Remove old DNS records
- Add network segmentation to context to indicate internal-only

### False Negatives (Reports Not Exposed When Actually Is)

**Causes:**
- WAF blocking HTTP probes
- CloudFlare/CDN blocking rate-limited requests
- Non-standard ports (8080, 3000, etc.)

**Solutions:**
- Allowlist Hawkeye's IP if possible
- Check WAF logs
- Use context file to manually specify exposure status

## Best Practices

1. **Run Detection in Production Environment**
   - Test from production-like infrastructure
   - This gives most accurate results

2. **Combine with Other Context**
   - Don't rely solely on exposure detection
   - Use firewall rules, auth gates, and segmentation context together

3. **Update Regularly**
   - Re-run exposure detection quarterly
   - Infrastructure changes can affect exposure status

4. **Version Your Context Files**
   - Track changes to context in git
   - Easier to track what changed between analyses

5. **Document Manual Overrides**
   - If you override exposure status, document why in context.custom
   - Helps teams understand non-obvious exposure status

## Technical Details

### DNS Query

Uses Google's public DNS-over-HTTPS API (`https://dns.google/resolve`):
- Queries A, AAAA, CNAME records
- Timeout: 5 seconds
- Cached for performance

### SSL Certificate

Uses Certificate Transparency logs via `api.crt.sh`:
- Queries CT logs for all certs matching domain
- Returns most recent certificate
- Timeout: 5 seconds

### HTTP Probes

Attempts HEAD requests to common endpoints:
- https://{domain}/
- https://api.{domain}/
- https://www.{domain}/
- Plus common subpaths: /api, /health, /api/health, /.well-known/security.txt

## Performance

- **Total Detection Time**: 5-20 seconds per domain
- **Parallelization**: All 3 methods run in parallel
- **Caching**: Results cached for 1 hour (configurable)
- **Network**: ~3 outbound HTTP/HTTPS requests

## Security Considerations

- **No Sensitive Data Sent**: Detection only looks at public DNS/SSL/HTTP
- **No Payload Inspection**: Doesn't analyze application responses
- **Rate Limited**: Respects API rate limits
- **Compliant**: Uses only public APIs (no scraping, no exploitation)

## Future Enhancements

Planned for Hawkeye v2.3+:

- Whois lookups for domain ownership verification
- Port scanning for non-standard port detection
- GeoIP analysis for datacenter location
- Secret scanning (API keys, credentials)
- Custom endpoint probes via context configuration
