# 🔒 Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Hawkeye, please **DO NOT** open a public GitHub issue.

Instead, please report it privately to:

📧 **Email**: lucasvsantos591@gmail.com

### What to Include

Please include:
- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact
- Suggested fix (if you have one)

### Response Timeline

We will:
1. Acknowledge receipt within 24 hours
2. Investigate and assess the severity
3. Develop a fix and notify you
4. Coordinate disclosure timeline with you

## Security Considerations for Users

### When Using Hawkeye

1. **API Keys**: Never commit API keys to your repository
   - Use environment variables
   - Use `.env` files (add to `.gitignore`)
   - Use secrets management tools

2. **What leaves your machine**:
   - Source code never does. Analysis runs locally.
   - Package names and versions go to `api.osv.dev` to look up advisories.
   - CVE ids go to `api.first.org` (EPSS); the CISA KEV catalog is downloaded as a whole.
   - Java projects without Maven/Gradle: POMs are fetched from Maven Central (or `HAWKEYE_MAVEN_REPO`).
   - `hawkeye expose <hostname>` queries `dns.google` and `crt.sh` with the hostname.
   - Point the `HAWKEYE_*_URL` variables at internal mirrors if package names are sensitive.

3. **AI Provider Choice** (optional, `hawkeye report --ai-provider`):
   - The provider receives, per finding: CVE id, package, versions, severity, reachability and the
     dependency path. No source code.
   - Choose providers you trust and review their API terms
   - For maximum privacy use `--ai-provider custom --ai-base-url` with a self-hosted OpenAI-compatible
     server (e.g. Ollama)

## Dependencies

Hawkeye uses open-source dependencies. We:
- Run `npm audit` regularly
- Keep dependencies updated
- Monitor security advisories
- Respond to reported issues promptly

---

**Thank you for helping keep Hawkeye secure!** 🙏
