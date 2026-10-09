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
   - `hawkeye expose <hostname>` resolves the hostname with your system DNS and connects to that host (TLS
     handshake, HTTP requests). No third-party service is queried.
   - Point the `HAWKEYE_*_URL` variables at internal mirrors if package names are sensitive.

3. **Analyzing untrusted repositories**:
   - By default Hawkeye runs nothing from the analyzed project. Source files are parsed, never executed;
     python3 runs isolated (`-I`, outside the project directory), so a module in the repository cannot
     shadow the standard library.
   - `--build-tool` (API: `HAWKEYE_ALLOW_BUILD_TOOLS=1`) runs `mvn`/`gradle` or the project's `./mvnw` /
     `./gradlew`, which executes its build scripts. Use it only on repositories you trust.
   - Child processes (python3, mvn, gradle) get a minimal environment (`PATH`, `HOME`, `JAVA_HOME`, proxy
     settings), never `HAWKEYE_API_TOKEN` or AI provider keys. A build script can still read files in
     your home directory (e.g. `~/.m2/settings.xml`), which is why build tools stay opt-in.

4. **AI Provider Choice** (optional, `hawkeye report --ai-provider`):
   - The provider receives, per finding: advisory id and summary, package, ecosystem, versions, severity,
     reachability, the dependency path, the remediation Hawkeye already planned, and the names of the
     package's functions/classes the project uses (e.g. `get`, `Session`). No source code.
   - The answer can only add code changes, an effort estimate and notes, marked with `ai_provider`. The
     fixed version, the command and the remediation type always come from the advisory, never from the model.
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
