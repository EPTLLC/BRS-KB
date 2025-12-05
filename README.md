<div align="center">

# BRS-KB

### Community XSS Knowledge Base

**Open Knowledge for Security Community**

_Advanced XSS Intelligence Database for Researchers and Scanners_

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/brs-kb.svg)](https://pypi.org/project/brs-kb/)
[![Version](https://img.shields.io/badge/version-3.0.0-green.svg)](https://github.com/EPTLLC/BRS-KB)
[![Code Size](https://img.shields.io/badge/code-19.5k%20lines-brightgreen.svg)]()
[![Contexts](https://img.shields.io/badge/contexts-27-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-334%20passing-success.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-81%25-green.svg)]()

## Table of Contents

- [Why BRS-KB?](#why-brs-kb)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Available Contexts](#available-contexts)
- [Features](#features)
- [CLI Tool](#cli-tool)
- [REST API Server](#rest-api-server)
- [Web UI](#web-ui)
- [Security Scanner Plugins](#security-scanner-plugins)
- [SIEM Integration](#siem-integration)
- [CI/CD Pipeline](#cicd-pipeline)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Contributing](#contributing)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Statistics](#statistics)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Project Info](#project-info)
- [Related Projects](#related-projects)
- [Support Policy](#support-policy)
- [Acknowledgments](#acknowledgments)

---

Comprehensive, community-driven knowledge base for Cross-Site Scripting (XSS) vulnerabilities

</div>

---

## Why BRS-KB?

| Feature | Description |
|---------|-------------|
| **27 Contexts** | Covering classic and modern XSS vulnerability types |
| **194+ Payloads** | Categorized with severity, tags, and WAF bypass info |
| **REST API** | Built-in HTTP server for Web UI and integrations |
| **Zero Dependencies** | Pure Python 3.8+ |
| **SIEM Compatible** | CVSS scores, CWE/OWASP mappings, severity levels |
| **Open Source** | MIT licensed, community contributions welcome |
| **Production Ready** | 81% test coverage, SQLite storage, modular architecture |

## Installation

### From PyPI (Recommended)
```bash
pip install brs-kb
```

### From Source
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e .
```

**Note:** On first run, the system will automatically migrate payloads from in-memory storage to SQLite database (`brs_kb/data/payloads.db`). You can also run `brs-kb migrate` manually.

### For Developers
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e ".[dev]"
```

**Requirements:** Python 3.8+ • No external dependencies

## Publishing to PyPI

### One-time Setup
```bash
# Setup PyPI configuration (one time only)
python3 scripts/publish.py setup

# Test publication process
python3 scripts/test_publish.py
```

### Publishing New Version
```bash
# Build and publish to PyPI
python3 scripts/publish.py

# Or manually:
python3 -m build
twine check dist/*
twine upload dist/*
```

## Quick Start

```python
from brs_kb import get_vulnerability_details, list_contexts

# Get detailed XSS context information
details = get_vulnerability_details('html_content')

print(details['title']) # Cross-Site Scripting (XSS) in HTML Content
print(details['severity']) # critical
print(details['cvss_score']) # 8.8
print(details['cwe']) # ['CWE-79']
print(details['owasp']) # ['A03:2021']

# List all available contexts
contexts = list_contexts()
# ['css_context', 'default', 'dom_xss', 'html_attribute', ...]
```

## Available Contexts

<details>
<summary><b>27 XSS Vulnerability Contexts</b> (click to expand)</summary>

### Core HTML Contexts
| Context | Description | Lines | Severity | CVSS |
|---------|-------------|-------|----------|------|
| `html_content` | XSS in HTML body/content | 407 | Critical | 8.8 |
| `html_attribute` | XSS in HTML attributes | 538 | Critical | 8.8 |
| `html_comment` | XSS in HTML comments | 77 | Medium | 5.4 |

### JavaScript Contexts
| Context | Description | Lines | Severity | CVSS |
|---------|-------------|-------|----------|------|
| `javascript_context` | Direct JavaScript injection | 645 | Critical | 9.0 |
| `js_string` | JavaScript string injection | 628 | Critical | 8.8 |
| `js_object` | JavaScript object injection | 628 | High | 7.8 |

### Style & Markup
| Context | Description | Lines | Severity | CVSS |
|---------|-------------|-------|----------|------|
| `css_context` | CSS injection & style attrs | 684 | High | 7.1 |
| `svg_context` | SVG-based XSS vectors | 297 | High | 7.3 |
| `markdown_context` | Markdown rendering XSS | 110 | Medium | 6.1 |

### Data Formats
| Context | Description | Lines | Severity | CVSS |
|---------|-------------|-------|----------|------|
| `json_value` | JSON context XSS | 81 | Medium | 6.5 |
| `xml_content` | XML/XHTML XSS vectors | 90 | High | 7.1 |

### Advanced Vectors
| Context | Description | Lines | Severity | CVSS |
|---------|-------------|-------|----------|------|
| `url_context` | URL/protocol-based XSS | 554 | High | 7.5 |
| `dom_xss` | DOM-based XSS (client-side) | 359 | High | 7.4 |
| `template_injection` | Client-side template injection | 116 | Critical | 8.6 |
| `postmessage_xss` | PostMessage API vulnerabilities | 134 | High | 7.4 |
| `wasm_context` | WebAssembly context XSS | 119 | Medium | 6.8 |

### Modern Web Technologies (NEW)
| Context | Description | Lines | Severity | CVSS |
|---------|-------------|-------|----------|------|
| `websocket_xss` | WebSocket real-time XSS | 431 | High | 7.5 |
| `service_worker_xss` | Service Worker injection | 557 | High | 7.8 |
| `webrtc_xss` | WebRTC P2P communication XSS | 565 | High | 7.6 |
| `indexeddb_xss` | IndexedDB storage XSS | 577 | Medium | 6.5 |
| `webgl_xss` | WebGL shader injection | 611 | Medium | 6.1 |
| `shadow_dom_xss` | Shadow DOM encapsulation bypass | 539 | High | 7.3 |
| `custom_elements_xss` | Custom Elements XSS | 590 | High | 7.1 |
| `http2_push_xss` | HTTP/2 Server Push XSS | 558 | Medium | 6.8 |
| `graphql_xss` | GraphQL API injection | 642 | High | 7.4 |
| `iframe_sandbox_xss` | iframe sandbox bypass | 591 | Medium | 6.3 |

### Fallback
| Context | Description | Lines | Severity | CVSS |
|---------|-------------|-------|----------|------|
| `default` | Generic XSS information | 165 | High | 7.1 |

</details>

## Features

### Metadata Structure

Each context includes security metadata:

```python
{
 # Core Information
 "title": "Cross-Site Scripting (XSS) in HTML Content",
 "description": "Detailed vulnerability explanation...",
 "attack_vector": "Real-world attack techniques...",
 "remediation": "Actionable security measures...",
 
 # Security Metadata
 "severity": "critical", # low | medium | high | critical
 "cvss_score": 8.8, # CVSS 3.1 base score
 "cvss_vector": "CVSS:3.1/...", # Full CVSS vector string
 "reliability": "certain", # tentative | firm | certain
 "cwe": ["CWE-79"], # CWE identifiers
 "owasp": ["A03:2021"], # OWASP Top 10 mapping
 "tags": ["xss", "html", "reflected"] # Classification tags
}
```

### Enhanced Reverse Mapping System

Advanced payload analysis with automatic context detection and ML-ready features:

```python
from brs_kb.reverse_map import find_contexts_for_payload, get_defenses_for_context, predict_contexts_ml_ready

# Automatic context detection with confidence scoring
info = find_contexts_for_payload("<script>alert(1)</script>")
# → {'contexts': ['html_content'],
# 'severity': 'critical',
# 'confidence': 1.0,
# 'analysis_method': 'pattern_matching',
# 'matched_patterns': 1}

# Modern XSS context detection
websocket_info = find_contexts_for_payload('WebSocket("wss://evil.com")')
# → {'contexts': ['websocket_xss'], 'severity': 'high', 'confidence': 1.0}

# ML-ready analysis with feature extraction
ml_analysis = predict_contexts_ml_ready('<script>alert(document.cookie)</script>')
# → {'contexts': ['html_content'], 'features': {'length': 39, 'has_script': True, ...}}

# Enhanced defense mapping with modern techniques
defenses = get_defenses_for_context('websocket_xss')
# → [{'defense': 'input_validation', 'priority': 1, 'required': True, 'tags': ['websocket']},
# {'defense': 'csp', 'priority': 1, 'required': True, 'tags': ['policy']}, ...]
```

## CLI Tool

BRS-KB includes a comprehensive command-line interface for security research and testing:

```bash
# Install the package
pip install brs-kb

# Show all available commands
brs-kb --help

# Show system information
brs-kb info

# List all XSS contexts
brs-kb list-contexts

# Get detailed information about a context
brs-kb get-context websocket_xss

# Analyze a payload
brs-kb analyze-payload "<script>alert(1)</script>"

# Search payloads in database
brs-kb search-payloads websocket --limit 5

# Test payload effectiveness
brs-kb test-payload "<script>alert(1)</script>" html_content

# Generate comprehensive report
brs-kb generate-report

# Validate database integrity
brs-kb validate

# Export data
brs-kb export contexts --format json --output contexts.json

# Set language
brs-kb language ru

# Migrate to SQLite database
brs-kb migrate

# Start API server for Web UI
brs-kb serve

# Start API server on custom port with metrics
brs-kb serve --port 8080 --metrics
```

**Available Commands:**
- `info` - Show system information and statistics
- `list-contexts` - List all available XSS contexts with severity
- `get-context <name>` - Get detailed vulnerability information
- `analyze-payload <payload>` - Analyze payload with reverse mapping
- `search-payloads <query>` - Search payload database with relevance scoring
- `test-payload <payload> <context>` - Test payload effectiveness in context
- `generate-report` - Generate comprehensive system analysis
- `validate` - Validate payload database integrity
- `export <type> --format <format>` - Export data (payloads, contexts, reports)
- `language [lang]` - Set or list supported languages (EN, RU, ZH, ES)
- `migrate [--force]` - Migrate payloads to SQLite database
- `serve [--port PORT] [--host HOST] [--metrics]` - Start REST API server for Web UI

## Usage

### 1. Security Scanner Integration

```python
from brs_kb import get_vulnerability_details

def enrich_finding(context_type, url, payload):
 kb_data = get_vulnerability_details(context_type)
 
 return {
 'url': url,
 'payload': payload,
 'title': kb_data['title'],
 'severity': kb_data['severity'],
 'cvss_score': kb_data['cvss_score'],
 'cwe': kb_data['cwe'],
 'description': kb_data['description'],
 'remediation': kb_data['remediation']
 }

# Use in scanner
finding = enrich_finding('dom_xss', 'https://target.com/app', 'location.hash')
```

### 2. SIEM/SOC Integration

```python
from brs_kb import get_vulnerability_details

def create_security_event(context, source_ip, target_url):
 kb = get_vulnerability_details(context)
 
 return {
 'event_type': 'xss_detection',
 'severity': kb['severity'],
 'cvss_score': kb['cvss_score'],
 'cvss_vector': kb['cvss_vector'],
 'cwe': kb['cwe'],
 'owasp': kb['owasp'],
 'source_ip': source_ip,
 'target': target_url,
 'requires_action': kb['severity'] in ['critical', 'high']
 }
```

### 3. Bug Bounty Reporting

```python
from brs_kb import get_vulnerability_details

def generate_report(context, url, payload):
 kb = get_vulnerability_details(context)
 
 return f"""
# {kb['title']}

**Severity**: {kb['severity'].upper()} (CVSS {kb['cvss_score']})
**CWE**: {', '.join(kb['cwe'])}

## Vulnerable URL
{url}

## Proof of Concept
```
{payload}
```

## Description
{kb['description']}

## Remediation
{kb['remediation']}
"""
```

### 4. Training & Education

```python
from brs_kb import list_contexts, get_vulnerability_details

# Create XSS learning materials
for context in list_contexts():
 details = get_vulnerability_details(context)
 
 print(f"Context: {context}")
 print(f"Severity: {details.get('severity', 'N/A')}")
 print(f"Attack vectors: {details['attack_vector'][:200]}...")
 print("-" * 80)
```

## Security Scanner Plugins

BRS-KB includes plugins for popular security testing tools:

### Burp Suite Plugin
- Real-time XSS payload analysis during proxying
- Automatic context detection for intercepted requests
- Integration with 27 XSS contexts
- Professional security team interface

**Installation:** Copy `plugins/burp_suite/BRSKBExtension.java` to Burp extensions

### OWASP ZAP Integration
- Automated XSS scanning with BRS-KB intelligence
- Context-aware payload injection
- WAF bypass technique detection
- Professional security workflow support

**Installation:** Load `plugins/owasp_zap/brs_kb_zap.py` in ZAP scripts

### Nuclei Templates
- 200+ categorized XSS payloads
- Context-specific testing (27 XSS contexts)
- WAF bypass technique detection

**Installation:** Copy templates to Nuclei templates directory

## SIEM Integration

BRS-KB integrates with enterprise SIEM systems for real-time XSS monitoring and alerting.

| Platform | Features | Installation |
|----------|----------|--------------|
| **Splunk** | Dashboards, alerting, trend analysis | `siem_connectors/splunk/brs_kb_app.tar.gz` |
| **Elasticsearch** | Kibana dashboards, ML anomaly detection | `siem_connectors/elastic/` |
| **Graylog** | GELF integration, stream processing | `siem_connectors/graylog/` |

### Quick Setup
```bash
# Splunk
cp siem_connectors/splunk/brs_kb_app.tar.gz $SPLUNK_HOME/etc/apps/

# Elasticsearch (Logstash)
cp siem_connectors/elastic/logstash.conf /etc/logstash/conf.d/

# Graylog
# Import content pack via Graylog UI
```

See [siem_connectors/README.md](siem_connectors/README.md) for detailed configuration.

## CI/CD Pipeline

BRS-KB includes comprehensive CI/CD configurations for automated testing and deployment:

### GitLab CI (`.gitlab-ci.yml`)
- Multi-Python version testing (3.8-3.12)
- Code quality checks and security scanning
- Package building and PyPI deployment
- Performance testing and coverage reporting

### GitLab CI (`.gitlab-ci.yml`) - Advanced Configuration
- Parallel testing across Python versions
- Package building and deployment
- Documentation deployment (GitLab Pages)
- Performance and security testing

### Jenkins Pipeline (`Jenkinsfile`)
- Declarative pipeline with parallel execution
- Artifact management and deployment
- Notification integration and reporting
- Enterprise-grade pipeline management

### Setup Script (`scripts/setup_cicd.py`)
Automated CI/CD pipeline setup and configuration.

**Quick Setup:**
```bash
python3 scripts/setup_cicd.py
```

See [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) for detailed CI/CD documentation.

## Multi-Language Documentation

BRS-KB includes comprehensive documentation in multiple languages:

### Available Languages
- **English (EN)** - Primary documentation (this file)
- **Russian (RU)** - [docs/README.ru.md](docs/README.ru.md)
- **Chinese (ZH)** - [docs/README.zh.md](docs/README.zh.md)
- **Spanish (ES)** - [docs/README.es.md](docs/README.es.md)

### Language Switching
```bash
brs-kb language ru    # Switch to Russian
brs-kb language zh    # Switch to Chinese
brs-kb language es    # Switch to Spanish
brs-kb language en    # Switch to English
brs-kb language --list  # List all supported languages
```

### Web UI Localization
The Web UI supports full localization in all 4 languages:
- Localized interface elements
- Context-specific examples
- Security terminology adaptation

## REST API Server

BRS-KB includes a built-in REST API server for Web UI integration and programmatic access:

### Starting the Server
```bash
# Start API server (default: http://0.0.0.0:8080)
brs-kb serve

# Custom port and host
brs-kb serve --port 9000 --host 127.0.0.1

# With Prometheus metrics endpoint
brs-kb serve --metrics --metrics-port 8000
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/info` | GET | System information |
| `/api/health` | GET | Health check |
| `/api/contexts` | GET | List all XSS contexts |
| `/api/contexts/<id>` | GET | Get context details |
| `/api/payloads` | GET | List payloads (with filters) |
| `/api/payloads/search?q=<query>` | GET | Search payloads |
| `/api/analyze` | GET/POST | Analyze payload |
| `/api/defenses?context=<ctx>` | GET | Get recommended defenses |
| `/api/stats` | GET | Platform statistics |
| `/api/languages` | GET | Supported languages |
| `/api/language` | POST | Set language |

### Python API
```python
from brs_kb import start_api_server, start_metrics_server

# Start API server programmatically
server = start_api_server(port=8080, host='0.0.0.0')

# Start metrics server for Prometheus
metrics = start_metrics_server(port=8000)

# Check if running
print(server.is_running())  # True

# Stop servers
server.stop()
metrics.stop()
```

## Web UI

BRS-KB includes a modern React-based web interface for visual exploration and testing:

### Web Interface (`web_ui/`)
**BRSKB Web UI** - Modern React-based web interface with full API integration

**Features:**
- Visual exploration of 27 XSS contexts
- Interactive playground for payload analysis
- Real-time statistics dashboard
- Payloads browser with search and filtering
- API documentation viewer
- Multi-language support (EN, RU, ZH, ES)
- Responsive design for all devices
- Automatic fallback when API unavailable

**Pages:**
- **Home** - Overview and quick stats
- **Contexts** - Browse all XSS vulnerability contexts
- **Payloads** - Search and filter 194+ payloads
- **Playground** - Interactive payload analyzer
- **Dashboard** - Statistics and charts
- **API Docs** - REST API documentation

**Installation:**
```bash
# Terminal 1: Start API server
brs-kb serve --port 8080

# Terminal 2: Start Web UI
cd web_ui
npm install
npm start
```

**Configuration:**
Set `REACT_APP_API_URL` environment variable to change API endpoint:
```bash
REACT_APP_API_URL=http://localhost:8080/api npm start
```

**Access:** `http://localhost:3000` after starting development server

See [web_ui/README.md](web_ui/README.md) for detailed Web UI documentation.

## Examples

See [examples/](examples/) directory for integration examples:

| Example | Description |
|---------|-------------|
| [`basic_usage.py`](examples/basic_usage.py) | Basic API usage and functionality |
| [`scanner_integration.py`](examples/scanner_integration.py) | Integration into security scanners |
| [`reverse_mapping.py`](examples/reverse_mapping.py) | Enhanced reverse mapping with ML-ready features |
| [`payload_database.py`](examples/payload_database.py) | 200+ payload database with testing API |
| [`cli_demo.py`](examples/cli_demo.py) | Command-line interface demonstration |
| [`plugin_demo.py`](examples/plugin_demo.py) | Security scanner plugin integration |
| [`cicd_demo.py`](examples/cicd_demo.py) | CI/CD pipeline demonstration |
| [`multilanguage_demo.py`](examples/multilanguage_demo.py) | Multi-language support demonstration |
| [`integrated_demo.py`](examples/integrated_demo.py) | Complete system integration showcase |

**Run examples:**
```bash
# Python examples
python3 examples/basic_usage.py
python3 examples/scanner_integration.py
python3 examples/cli_demo.py
python3 examples/plugin_demo.py
python3 examples/integrated_demo.py

# CLI commands
brs-kb info # System information
brs-kb list-contexts # All XSS contexts
brs-kb get-context websocket_xss # Context details
brs-kb analyze-payload "<script>alert(1)</script>" # Payload analysis
brs-kb search-payloads websocket --limit 5 # Search payloads
brs-kb test-payload "<script>alert(1)</script>" html_content # Test effectiveness
brs-kb generate-report # Comprehensive report
brs-kb validate # Database validation
brs-kb export contexts --format json # Export data

# Security scanner integration
nuclei -t plugins/nuclei/templates/brs-kb-xss.yaml -u https://target.com

# SIEM integration
python3 siem_connectors/splunk/brs_kb_splunk_connector.py --api-key YOUR_KEY --splunk-url https://splunk.company.com:8088

# CI/CD pipeline
python3 scripts/setup_cicd.py

# Multi-language support
brs-kb language ru
brs-kb language --list
```

## API Reference

### Core Functions

#### `get_vulnerability_details(context: str) -> Dict[str, Any]`
Get detailed information about a vulnerability context.

```python
details = get_vulnerability_details('html_content')
```

#### `list_contexts() -> List[str]`
Get list of all available contexts.

```python
contexts = list_contexts() # ['css_context', 'default', 'dom_xss', ...]
```

#### `get_kb_info() -> Dict[str, Any]`
Get knowledge base information (version, build, contexts count).

```python
info = get_kb_info()
print(f"Version: {info['version']}, Total contexts: {info['total_contexts']}")
```

#### `get_kb_version() -> str`
Get version string.

```python
version = get_kb_version() # "1.0.0"
```

### Enhanced Reverse Mapping Functions

Import from `brs_kb.reverse_map`:

#### `find_contexts_for_payload(payload: str) -> Dict`
Advanced payload analysis with automatic context detection and confidence scoring.

#### `predict_contexts_ml_ready(payload: str) -> Dict`
ML-ready analysis with feature extraction for future machine learning integration.

#### `get_defenses_for_context(context: str) -> List[Dict]`
Get recommended defenses for a context with enhanced metadata and implementation details.

#### `get_defense_info(defense: str) -> Dict`
Get comprehensive information about a defense mechanism including bypass difficulty and tags.

#### `analyze_payload_with_patterns(payload: str) -> List[Tuple]`
Analyze payload against pattern database returning matches with confidence scores.

#### `get_reverse_map_info() -> Dict`
Get reverse mapping system information including version, capabilities, and statistics.

#### `reverse_lookup(query_type: str, query: str) -> Dict`
Universal lookup function supporting payload, context, defense, and pattern queries.

### Payload Database Functions

#### `get_payloads_by_context(context: str) -> List[Dict]`
Get all payloads effective in a specific context.

#### `get_payloads_by_severity(severity: str) -> List[Dict]`
Get all payloads by severity level.

#### `search_payloads(query: str) -> List[Dict]`
Search payloads with relevance scoring.

#### `test_payload_in_context(payload: str, context: str) -> Dict`
Test payload effectiveness in specific context.

#### `get_database_info() -> Dict`
Get payload database statistics and information.

### CLI Tool Functions

#### `get_cli() -> BRSKBCLI`
Get CLI instance for programmatic use.

**CLI Commands:**
- `brs-kb info` - System information
- `brs-kb list-contexts` - List all XSS contexts
- `brs-kb get-context <name>` - Context details
- `brs-kb analyze-payload <payload>` - Payload analysis
- `brs-kb search-payloads <query>` - Search payloads
- `brs-kb test-payload <payload> <context>` - Test effectiveness
- `brs-kb generate-report` - Comprehensive report
- `brs-kb validate` - Database validation
- `brs-kb export <type>` - Export data

## Contributing

Contributions from the security community are welcome.

### Ways to Contribute

- Add new XSS contexts
- Update existing contexts with new bypasses
- Improve documentation
- Report issues or outdated information
- Share real-world examples

**Quick start:**
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
git checkout -b feature/new-context
# Make changes
pytest tests/ -v
git commit -m "Add: New context for WebSocket XSS"
git push origin feature/new-context
# Open Pull Request
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Project Structure

```
BRS-KB/
 brs_kb/ # Main package
 __init__.py # Core API with public exports
 api_server.py # REST API server for Web UI
 metrics_server.py # Prometheus metrics server
 schema.json # JSON Schema validation
 reverse_map.py # Reverse mapping wrapper (backward compatibility)
 reverse_map/ # Reverse mapping package (modular)
   __init__.py
   patterns.py # Context detection patterns
   defenses.py # Defense strategies
   analysis.py # Payload analysis
   utils.py # Utility functions
 i18n.py # Internationalization system
 cli.py # CLI wrapper (backward compatibility)
 cli/ # CLI package (modular)
   __init__.py
   __main__.py # Module execution entry point
   cli.py # Main CLI class
   parser.py # Argument parser
   commands/ # Individual command modules
     base.py # Base command class
     list_contexts.py
     get_context.py
     analyze_payload.py
     search_payloads.py
     test_payload.py
     generate_report.py
     info.py
     validate.py
     export.py
     language.py
     migrate.py
     serve.py # API server command
 payload_testing.py # Payload testing framework
 payloads_db.py # Payload database wrapper (backward compatibility)
 payloads_db/ # Payload database package (modular)
   __init__.py
   data.py # In-memory database
   models.py # Data models
   operations.py # CRUD operations
   queries.py # Query functions
   search.py # Search functionality
   info.py # Database info
   testing.py # Testing utilities
 payloads_db_sqlite.py # SQLite database implementation
 migrations.py # Database migrations
 contexts/ # 27 vulnerability contexts
 html_content.py
 javascript_context.py
 websocket_xss.py
 ...
 examples/ # Integration examples
 tests/ # Test suite (pytest, 334 tests, 81% coverage)
 docs/ # Multi-language documentation
 i18n/locales/ # Translation files
 plugins/ # Security scanner plugins
 siem_connectors/ # SIEM system integrations
 web_ui/ # React-based web interface
   src/
     services/api.js # API client for backend
     pages/ # Page components
     components/ # UI components
 LICENSE # MIT License
 CONTRIBUTING.md # Contribution guide
 CHANGELOG.md # Version history
 README.md # This file
```

## Testing

```bash
# Run all tests (334 tests)
pytest tests/ -v

# Run with coverage (81% coverage)
pytest tests/ -v --cov=brs_kb --cov-report=term-missing

# Run specific test modules
pytest tests/test_basic.py -v          # Basic functionality
pytest tests/test_cli.py -v            # CLI commands
pytest tests/test_sqlite.py -v         # SQLite database
pytest tests/test_api_server.py -v     # REST API server
pytest tests/test_metrics_server.py -v # Prometheus metrics
```

**Test Coverage:** 81% (334 tests passing)

## Statistics

| Metric | Value |
|--------|-------|
| Total Lines | ~19,500+ |
| Context Modules | 27 |
| Payload Database | 194+ |
| Test Coverage | 81% (334 tests) |
| CLI Commands | 12 commands |
| REST API Endpoints | 13 |
| Reverse Mapping Patterns | 29 |
| Security Scanner Plugins | 3 platforms |
| SIEM Integrations | 3 systems |
| Multi-Language Support | 4 languages |
| External Dependencies | 0 |
| Python Version | 3.8+ |

### Features Checklist

| Feature | Status |
|---------|--------|
| REST API Server | Supported |
| Prometheus Metrics | Supported |
| Web UI (React 18) | Supported |
| SQLite Database | Supported |
| Multi-Language Support | EN, RU, ZH, ES |
| Docker Support | Supported |
| Kubernetes Support | Supported |
| CI/CD Pipelines | GitHub, GitLab, Jenkins |
| ML-Ready Features | Supported |
| WAF Bypass Detection | 15+ payloads |
| Modern XSS Contexts | WebSocket, WebRTC, GraphQL, etc. |

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'brs_kb'` | Run `pip install -e .` from project root |
| SQLite database not created | Run `brs-kb migrate` or check write permissions to `brs_kb/data/` |
| API server port already in use | Use `--port` flag: `brs-kb serve --port 9000` |
| Web UI cannot connect to API | Verify API server is running, check CORS and `REACT_APP_API_URL` |
| Tests failing on import | Ensure you're using Python 3.8+ |

### Database Issues

```bash
# Force database recreation
brs-kb migrate --force

# Check database location
python3 -c "from brs_kb.payloads_db import get_database_info; print(get_database_info())"

# Verify database integrity
brs-kb validate
```

### API Server Issues

```bash
# Check if port is available
lsof -i :8080

# Start with verbose logging
brs-kb serve --port 8080 2>&1 | tee server.log

# Test API health
curl http://localhost:8080/api/health
```

### Web UI Issues

```bash
# Clear npm cache and reinstall
cd web_ui
rm -rf node_modules package-lock.json
npm install

# Check API connection
curl http://localhost:8080/api/info
```

## License

**MIT License** - Free to use in any project (commercial or non-commercial)

```
Copyright (c) 2025 EasyProTech LLC / Brabus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

See [LICENSE](LICENSE) for full text.

## Project Info

| | |
|---|---|
| **Project** | BRS-KB (BRS XSS Knowledge Base) |
| **Company** | EasyProTech LLC |
| **Website** | [www.easypro.tech](https://www.easypro.tech) |
| **Developer** | Brabus |
| **Contact** | [https://t.me/easyprotech](https://t.me/easyprotech) |
| **Repository** | [https://github.com/EPTLLC/BRS-KB](https://github.com/EPTLLC/BRS-KB) |
| **License** | MIT |
| **Status** | Production-Ready |
| **Version** | 3.0.0 |

## Related Projects

- **[BRS-XSS](https://github.com/EPTLLC/brs-xss)** - Advanced XSS Scanner (uses BRS-KB)

## Support Policy

**NO OFFICIAL SUPPORT PROVIDED**

This is a community-driven project. While we welcome contributions:
- Use GitHub Issues for bug reports
- Use Pull Requests for contributions
- No SLA or guaranteed response time

This project is maintained by the community.

## Acknowledgments

- Security researchers who contribute knowledge
- Open-source community for support
- Everyone who reports issues and improvements

---

<div align="center">

**Open Source XSS Knowledge Base**

*MIT License • Python 3.8+ • Zero Dependencies*

</div>
