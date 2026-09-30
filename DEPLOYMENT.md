# 🚀 Hawkeye Deployment Guide

## Quick Start for Production

### Prerequisites
- Node.js 18+
- npm 9+
- Docker (optional, for containerization)

### Installation

```bash
# Clone the repository
git clone https://github.com/lucasvsantos591-hue/hawkeye.git
cd hawkeye

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test
```

### Usage Modes

#### 1. **Command-Line Mode** (Single Project)
```bash
# Analyze a single project
node dist/cli/index.js analyze /path/to/project --level 2 --output results.json

# Generate HTML report
node dist/cli/index.js report results.json --format html --output report.html

# Generate SARIF export
node dist/cli/index.js report results.json --format sarif --output results.sarif
```

#### 2. **Batch Processing** (Multiple Projects)
```bash
# Analyze multiple projects concurrently
node dist/cli/index.js batch /path/to/projects --concurrency 4 --output results/
```

#### 3. **HTTP API Server** (Recommended for Production)
```bash
# Start the API server
node dist/cli/server.js --port 3000

# Then make requests:
# POST /api/analyze
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"projectPath": "/path/to/project"}'

# GET /api/health
curl http://localhost:3000/api/health
```

### Docker Deployment

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY dist ./dist

EXPOSE 3000

CMD ["node", "dist/cli/server.js", "--port", "3000"]
```

Build and run:
```bash
docker build -t hawkeye:latest .
docker run -p 3000:3000 hawkeye:latest
```

### Configuration

#### Environment Variables
- `HAWKEYE_PORT`: API server port (default: 3000)
- `HAWKEYE_CACHE_DIR`: Cache directory (default: ./.hawkeye-cache)
- `HAWKEYE_LOG_LEVEL`: Log level - debug/info/warn/error (default: info)
- `HAWKEYE_MAX_CONCURRENCY`: Max concurrent analyses (default: 4)

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

#### GitHub Actions
```yaml
name: Security Analysis

on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - run: npm ci
      - run: npm run build
      - run: npm test
      
      - name: Analyze
        run: node dist/cli/index.js analyze . --output results.json
      
      - name: Report
        run: node dist/cli/index.js report results.json --format html --output report.html
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.html
```

#### GitLab CI
```yaml
analyze:
  image: node:18
  script:
    - npm ci
    - npm run build
    - npm test
    - node dist/cli/index.js analyze . --output results.json
    - node dist/cli/index.js report results.json --format html --output report.html
  artifacts:
    paths:
      - report.html
    expire_in: 30 days
```

#### Azure Pipelines
```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '18.x'
  
  - script: npm ci
  - script: npm run build
  - script: npm test
  
  - script: node dist/cli/index.js analyze . --output results.json
  - script: node dist/cli/index.js report results.json --format html --output report.html
  
  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: 'report.html'
```

### Health Checks

```bash
# API Health
curl http://localhost:3000/api/health

# Expected response:
# {"status": "ok", "version": "1.0.0", "uptime": 3600}
```

### Monitoring

The API server includes built-in metrics:
- Response times per endpoint
- Cache hit/miss rates
- Analysis duration statistics
- Error rates by type

Access metrics at: `GET /api/metrics`

### Scaling

For production workloads:
1. **Horizontal Scaling**: Run multiple instances behind a load balancer
2. **Caching**: Use Redis backend for shared cache across instances
3. **Message Queue**: Queue large batch jobs using Redis/RabbitMQ
4. **Database**: Use SQLite cache for local persistence

### Security Considerations

1. **API Authentication**: Add authentication middleware before production
2. **Rate Limiting**: Implement rate limits to prevent abuse
3. **TLS/HTTPS**: Use reverse proxy with SSL/TLS
4. **Input Validation**: All project paths are validated
5. **Sandboxing**: Run analysis in isolated environment

### Troubleshooting

#### High Memory Usage
- Reduce concurrency: `--concurrency 2`
- Increase cache TTL for reuse
- Monitor with: `node dist/cli/index.js analyze . --verbose`

#### Slow Analysis
- Enable caching: `.hawkeye-cache` directory
- Run batch mode for multiple projects
- Check `--verbose` output for bottlenecks

#### Network Issues
- Check connectivity to CVE sources (NVD, CISA KEV)
- Use offline mode if needed
- Implement retry logic in CI/CD

### Support

- GitHub: https://github.com/lucasvsantos591-hue/hawkeye
- Issues: https://github.com/lucasvsantos591-hue/hawkeye/issues
- Discussions: https://github.com/lucasvsantos591-hue/hawkeye/discussions
