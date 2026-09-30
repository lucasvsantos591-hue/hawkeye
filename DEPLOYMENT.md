# 🚀 Hawkeye Deployment Guide

## Quick Start for Production

### Prerequisites
- Node.js 20+
- Outbound HTTPS to api.osv.dev, api.first.org, www.cisa.gov (and repo1.maven.org for Java projects)
- python3 for Python projects (included in the Docker image); Maven/Gradle optional for exact Java trees
- Docker (optional)

### Installation

```bash
git clone https://github.com/lucasvsantos591-hue/hawkeye.git
cd hawkeye
npm ci
npm run build
npm test
```

### Usage Modes

#### 1. Command line (single project)
```bash
node dist/cli/index.js analyze /path/to/project -o results.json
node dist/cli/index.js analyze /path/to/project -f html -o report.html
node dist/cli/index.js analyze /path/to/project -f sarif -o results.sarif
node dist/cli/index.js analyze /path/to/project --fail-on high   # exit code 2 on reachable HIGH+
node dist/cli/index.js report results.json --format html --output report.html
```

#### 2. Batch (every subdirectory with a package.json)
```bash
node dist/cli/index.js batch /path/to/projects --concurrency 2 --output results/
```

#### 3. HTTP API
```bash
HAWKEYE_API_TOKEN=change-me HAWKEYE_ALLOWED_ROOT=/srv/repos node dist/cli/server.js

curl http://localhost:3000/api/health
curl -X POST http://localhost:3000/api/analyze \
  -H "Authorization: Bearer change-me" \
  -d '{"projectPath": "my-repo", "level": 2, "format": "json"}'
```

`projectPath` is resolved inside `HAWKEYE_ALLOWED_ROOT`; anything outside it (including via symlinks)
returns 403. `format` can be `json`, `html` or `sarif`. `POST /api/report` takes
`{ "analysisResult": {...}, "format": "html" | "sarif" | "json" }`.

### Docker Deployment

The [Dockerfile](./Dockerfile) builds from source in a multi-stage build and runs as the `node` user.

```bash
docker build -t hawkeye:latest .
docker run -p 3000:3000 \
  -e HAWKEYE_API_TOKEN=change-me \
  -v /srv/repos:/workspace:ro \
  hawkeye:latest

# One-off CLI scan with the same image
docker run --rm -v "$PWD:/workspace:ro" hawkeye:latest \
  node dist/cli/index.js analyze /workspace --no-cache > results.json
```

### Configuration

#### Environment Variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `HAWKEYE_API_TOKEN` | (none) | Bearer token. Required unless the server listens on localhost |
| `HAWKEYE_HOST` | `127.0.0.1` (`0.0.0.0` in Docker) | Listen address |
| `HAWKEYE_PORT` | `3000` | Listen port |
| `HAWKEYE_ALLOWED_ROOT` | current directory (`/workspace` in Docker) | Only projects under this path can be analyzed |
| `HAWKEYE_MAX_CONCURRENCY` | `2` | Concurrent analyses before the API returns 429 |
| `HAWKEYE_CORS_ORIGIN` | (none) | Set to allow one browser origin |
| `HAWKEYE_CACHE_DIR` | `~/.cache/hawkeye` | Cache for OSV/EPSS/KEV responses |
| `HAWKEYE_OSV_URL`, `HAWKEYE_EPSS_URL`, `HAWKEYE_KEV_URL` | public APIs | Point at mirrors if needed |
| `HAWKEYE_MAVEN_REPO` | `https://repo1.maven.org/maven2` | Maven repository used to resolve POMs when mvn/gradle is not run |
| `HAWKEYE_ALLOW_BUILD_TOOLS` | (unset) | `1` lets the API run mvn/gradle (executes the analyzed project's build scripts) |

#### Context File (.hawkeye.yaml)
```yaml
application_name: my-app
environment: production
exposure: internet-facing

network_location:
  aws_region: us-east-1
  public_ips:
    - 203.0.113.0

compliance:
  pci_dss: true
  gdpr: true

custom_tags:
  team: security
  owner: john@example.com
```

### CI/CD Integration

#### GitHub Actions (scan your application repo)
```yaml
name: Hawkeye

on: [push, pull_request]

jobs:
  hawkeye:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Build Hawkeye
        run: |
          git clone --depth 1 https://github.com/lucasvsantos591-hue/hawkeye.git /tmp/hawkeye
          cd /tmp/hawkeye && npm ci && npm run build
      - name: Analyze
        run: node /tmp/hawkeye/dist/cli/index.js analyze . -f sarif -o hawkeye.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: hawkeye.sarif
      - name: Gate on reachable HIGH+
        run: node /tmp/hawkeye/dist/cli/index.js analyze . --fail-on high > /dev/null
```

#### GitLab CI
```yaml
hawkeye:
  image: node:20
  script:
    - git clone --depth 1 https://github.com/lucasvsantos591-hue/hawkeye.git /tmp/hawkeye
    - (cd /tmp/hawkeye && npm ci && npm run build)
    - node /tmp/hawkeye/dist/cli/index.js analyze . -f html -o hawkeye.html
    - node /tmp/hawkeye/dist/cli/index.js analyze . --fail-on high > hawkeye.json
  artifacts:
    when: always
    paths: [hawkeye.html, hawkeye.json]
    expire_in: 30 days
```

#### Azure Pipelines
```yaml
pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '20.x'
  - script: |
      git clone --depth 1 https://github.com/lucasvsantos591-hue/hawkeye.git $(Agent.TempDirectory)/hawkeye
      cd $(Agent.TempDirectory)/hawkeye && npm ci && npm run build
    displayName: Build Hawkeye
  - script: node $(Agent.TempDirectory)/hawkeye/dist/cli/index.js analyze . -f html -o hawkeye.html
  - script: node $(Agent.TempDirectory)/hawkeye/dist/cli/index.js analyze . --fail-on high > hawkeye.json
  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      pathToPublish: 'hawkeye.html'
```

### Health Checks

```bash
# API Health
curl http://localhost:3000/api/health

# Expected response:
# {"status":"ok","version":"0.2.0","uptime":3600,"busy":0}
```

### Scaling

Each analysis is CPU-bound (Babel parsing), so a 2,000-file repo takes about 5s. For more throughput,
run several instances behind a load balancer and share `HAWKEYE_CACHE_DIR` on a volume, which cuts
repeated OSV/EPSS/KEV lookups.

### Security Considerations

1. **Authentication**: bearer token (`HAWKEYE_API_TOKEN`), compared in constant time
2. **Path allow-list**: `HAWKEYE_ALLOWED_ROOT`, checked after resolving symlinks
3. **Limits**: 5 MB request bodies, `HAWKEYE_MAX_CONCURRENCY` concurrent analyses
4. **TLS**: not built in. Put a reverse proxy in front
5. **Least privilege**: the container runs as `node`; mount repositories read-only

### Troubleshooting

- **"No usable lockfile found"**: commit `package-lock.json`, `yarn.lock` or `pnpm-lock.yaml`. Without one
  only direct dependencies at their minimum range version are checked.
- **Network errors**: the scan needs api.osv.dev (required), api.first.org and www.cisa.gov (optional:
  failures show up as warnings in `scan.warnings`). Behind a proxy, point `HAWKEYE_*_URL` at a mirror.
- **A package you know is used shows as "never imported"**: it is probably loaded indirectly (framework
  plugin, config string, CLI). Treat it as reachable and open an issue with the example.
- **Files that fail to parse** are listed in `scan.warnings`. The rest of the project is still analyzed.

### Support

- GitHub: https://github.com/lucasvsantos591-hue/hawkeye
- Issues: https://github.com/lucasvsantos591-hue/hawkeye/issues
- Discussions: https://github.com/lucasvsantos591-hue/hawkeye/discussions
