# Vulnerability Reachability Analyzer (VRA)

> **Intelligent CVE Validation** | Go beyond version-based vulnerability scanning to determine if a vulnerability is actually exploitable in your codebase.

## 🎯 The Problem

Traditional SCA (Software Composition Analysis) tools flag any package version with a known CVE as vulnerable—even if your code never uses the vulnerable function.

**Example:**
```javascript
// Your code
import axios from 'axios'; // CVE-2023-XXXX in axios < 1.4.0

export function fetchData() {
  // Only uses safe methods
  return axios.get('/api/data');
}
```

Traditional scanner: ⚠️ **VULNERABLE**
VRA: ✅ **SAFE** (vulnerable function not called)

---

## ✨ Features

### 🔍 Three Levels of Reachability Analysis

1. **Level 1: Import Detection**
   - Checks if vulnerable package is imported
   - Fastest, lowest false negatives

2. **Level 2: Call Graph Analysis**
   - Builds complete call graph of your code
   - Determines if vulnerable function is reachable
   - Provides call chain from entry point to vulnerability

3. **Level 3: Data Flow & Taint Analysis**
   - Tracks how user input flows through your code
   - Identifies if tainted data reaches vulnerable sink
   - Most accurate, catches complex attack vectors

### 🌍 Multi-Language Support

- **JavaScript/TypeScript** (via Babel AST)
- **Python** (via AST module)
- **Java, Go, Rust** (roadmap)

### 📦 Multiple Vulnerability Sources

- **NVD API** (National Vulnerability Database)
- **Local SQLite Cache** (offline support)
- **Snyk API** (optional, planned)

### 🚀 Performance

- Aggressive caching reduces API calls by 95%
- Parallel analysis of multiple dependencies
- Call graph built once, reused for all CVEs

---

## 🚀 Quick Start

### Prerequisites

- Dart 3.0+
- Node.js 18+
- Python 3.10+
- Make

### Installation

```bash
git clone https://github.com/your-org/vra-project.git
cd vra-project
make setup
```

### Basic Usage

```bash
# Analyze a JavaScript/TypeScript project
vra analyze ./my-nodejs-app --level 2

# Analyze a Python project
vra analyze ./my-python-app --language python --level 3

# Generate HTML report
vra analyze ./my-app --format html --output report.html

# Check specific CVE
vra scan axios 1.4.0 --language javascript
```

---

## 📊 Sample Output

```json
{
  "project_name": "my-app",
  "total_vulnerabilities": 15,
  "reachable_vulnerabilities": 3,
  "overall_risk_score": 42,
  "results": [
    {
      "vulnerability": {
        "cve_id": "CVE-2023-12345",
        "package": "express",
        "severity": "HIGH",
        "affected_versions": ["<4.17.1"]
      },
      "is_reachable": true,
      "reachability_level": 2,
      "confidence": 92,
      "call_chain": [
        "main",
        "setupRoutes",
        "handleRequest",
        "vulnerableFunction"
      ],
      "remediation_advice": "Upgrade express to >=4.17.1"
    },
    {
      "vulnerability": {
        "cve_id": "CVE-2023-54321",
        "package": "lodash",
        "severity": "MEDIUM",
        "affected_versions": ["<4.17.20"]
      },
      "is_reachable": false,
      "reachability_level": 1,
      "confidence": 100,
      "remediation_advice": "No action needed - vulnerable function not used"
    }
  ]
}
```

---

## 🏗️ Architecture

```
vulnerability-reachability-engine/
├── core/                      # Zero-dependency Dart core
├── adapters/                  # Language parsers & API adapters
│   ├── parsers/
│   │   ├── js_typescript_parser/
│   │   └── python_parser/
│   └── vulnerability_sources/
│       ├── nvd_api_adapter.ts
│       └── local_db_adapter.dart
├── cli/                       # Command-line interface
├── integration/               # Samburá connector
└── tests/                     # Comprehensive test suite
```

---

## 📚 Documentation

- [Architecture Guide](./VULNERABILITY_ANALYZER_ARCHITECTURE.md)
- [API Reference](./docs/API.md)
- [Contributing Guidelines](./packages/sambura_core/CONTRIBUTING.md)
- [Configuration](./docs/CONFIG.md)

---

## 🧪 Testing

```bash
# Run all tests
make test

# Run specific test suite
make test-core
make test-cli
make test-e2e

# Watch mode
make test-watch

# Coverage report
make test-core -- --coverage
```

---

## 📦 Packages

### NPM
```bash
npm install vra-cli
```

### Pub.dev (Dart)
```bash
dart pub add vulnerability_reachability_analyzer
```

### PyPI (Python)
```bash
pip install vra-python-parsers
```

---

## 🔧 Configuration

Create a `.vrarc` file in your project root:

```json
{
  "language": "javascript",
  "reachability_level": 2,
  "cve_sources": ["nvd", "local"],
  "cache_dir": "./.vra-cache",
  "exclude_packages": ["@types/*"],
  "entry_points": ["src/index.ts"],
  "output": {
    "format": "json",
    "path": "./report.json"
  }
}
```

---

## 🔌 Integration with Samburá

VRA can integrate with Samburá to enforce policies:

```dart
// In your Samburá gateway config
import 'package:vra_core/vra_core.dart';

final analyzer = ReachabilityAnalyzer();
final result = await analyzer.analyze(projectPath);

// Block deployments with critical reachable vulnerabilities
if (result.getCriticalReachable().isNotEmpty) {
  throw PolicyViolationException('Critical vulnerabilities detected');
}
```

---

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](./packages/sambura_core/CONTRIBUTING.md)

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -am 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](./LICENSE) file.

---

## 🙏 Acknowledgments

- Built with inspiration from OWASP and security research community
- Powered by Babel, AST module, and NVD
- Part of the Samburá ecosystem for secure software supply chains

---

## 📧 Support

- 📖 [Documentation](./docs)
- 🐛 [Issue Tracker](https://github.com/your-org/vra-project/issues)
- 💬 [Discussions](https://github.com/your-org/vra-project/discussions)
- 📧 Email: vra@example.com
