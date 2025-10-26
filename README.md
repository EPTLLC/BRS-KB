<div align="center">

# BRS-KB

### Community XSS Knowledge Base

**Open Knowledge for Security Community**

_Advanced XSS Intelligence Database for Researchers and Scanners_

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/brs-kb.svg)](https://pypi.org/project/brs-kb/)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/EPTLLC/BRS-KB)
[![Code Size](https://img.shields.io/badge/code-8.5k%20lines-brightgreen.svg)]()
[![Contexts](https://img.shields.io/badge/contexts-27-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-passing-success.svg)]()

## Table of Contents

- [Why BRS-KB?](#why-brs-kb)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Available Contexts](#available-contexts)
- [Features](#features)
- [CLI Tool](#cli-tool)
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
| **Detailed Info** | Attack vectors, bypass techniques, defense strategies |
| **Simple API** | Python library, easy to integrate |
| **Zero Dependencies** | Pure Python 3.8+ |
| **SIEM Compatible** | CVSS scores, CWE/OWASP mappings, severity levels |
| **Open Source** | MIT licensed, community contributions welcome |
| **In Production** | Used in security scanners and tools |

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
python -m build
twine check dist/*
twine upload dist/*
```

## Quick Start

```python
from brs_kb import get_vulnerability_details, list_contexts

# Context details
details = get_vulnerability_details('html_content')
print(details['title'], details['severity'], details['cvss_score'])

# Available contexts
contexts = list_contexts()
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
  "title": "Cross-Site Scripting (XSS) in HTML Content",
  "severity": "critical",
  "cvss_score": 8.8,
  "cwe": ["CWE-79"],
  "owasp": ["A03:2021"]
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
- Modern web technology testing

**Installation:** Copy templates to Nuclei templates directory

### SIEM Integration
BRS-KB integrates with enterprise SIEM systems for real-time monitoring:

#### Splunk Integration
- Real-time XSS vulnerability data ingestion
- Custom dashboards for XSS context analysis
- Alerting rules for critical vulnerabilities
- Historical trend analysis

**Installation:** Copy `siem_connectors/splunk/brs_kb_app.tar.gz` to Splunk apps directory

#### Elasticsearch Integration
- Logstash/Beats integration for BRS-KB data
- Kibana dashboards for XSS analysis
- Machine learning anomaly detection
- Elasticsearch Watcher alerting

**Installation:** Deploy Logstash configuration from `siem_connectors/elastic/`

#### Graylog Integration
- GELF integration for real-time log ingestion
- Custom dashboards and widgets
- Alerting rules and notifications
- Stream processing for XSS events

**Installation:** Import content pack from `siem_connectors/graylog/`

See [siem_connectors/README.md](siem_connectors/README.md) for detailed installation and usage instructions.

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
- ** English** - Primary documentation (this file)
- ** Русский** - [docs/README.ru.md](docs/README.ru.md)
- ** ** - [docs/README.zh.md](docs/README.zh.md)
- ** Español** - [docs/README.es.md](docs/README.es.md)

### Language Switching
Use the CLI to switch between languages:

```bash
brs-kb language ru # Switch to Russian
brs-kb language zh # Switch to Chinese
brs-kb language es # Switch to Spanish
brs-kb language en # Switch to English
brs-kb language --list # List all supported languages
```

All documentation includes localized examples, cultural context, and region-specific attack vectors.

### Web UI Localization
The Web UI also supports full localization in all 4 languages with:
- Localized interface elements
- Context-specific examples in each language
- Cultural adaptation for security terminology
- Region-specific attack vector descriptions

## Web UI

BRS-KB includes a modern React-based web interface for visual exploration and testing:

### Web Interface (`web_ui/`)
**BRSKB Web UI** - Modern React-based web interface

**Features:**
- Visual exploration of 27 XSS contexts
- Interactive playground for payload testing
- Real-time statistics dashboard
- Multi-language support (EN, RU, CN, ES)
- Responsive design for all devices

**Installation:**
```bash
cd web_ui
npm install
npm start
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
 __init__.py # Core API
 schema.json # JSON Schema validation
 reverse_map.py # Reverse mapping system
 i18n.py # Internationalization system
 cli.py # Command-line interface
 payload_testing.py # Payload testing framework
 payloads_db.py # Payload database
 contexts/ # 27 vulnerability contexts
 html_content.py
 javascript_context.py
 websocket_xss.py
 ...
 examples/ # Integration examples
 tests/ # Test suite (pytest)
 docs/ # Multi-language documentation
 i18n/locales/ # Translation files
 plugins/ # Security scanner plugins
 siem_connectors/ # SIEM system integrations
 web_ui/ # React-based web interface
 LICENSE # MIT License
 CONTRIBUTING.md # Contribution guide
 CHANGELOG.md # Version history
 README.md # This file
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage (requires pytest-cov)
pytest tests/ -v --cov=brs_kb

# Run specific test
pytest tests/test_basic.py -v
```

## Statistics

| Metric | Value |
|--------|-------|
| Total Lines | ~16,500+ |
| Context Modules | 27 |
| Payload Database | 200+ |
| Multi-Language Support | |
| Web UI | |
| Reverse Mapping Patterns | 29 |
| Supported Contexts | 27 |
| Average Module Size | 418 lines |
| Test Coverage | 33 tests |
| CLI Commands | 9 commands |
| Security Scanner Plugins | 3 platforms |
| SIEM Integrations | 3 systems |
| CI/CD Pipelines | GitLab CI, Jenkins |
| Deployment Scripts | |
| Docker Support | |
| Kubernetes Support | |
| Monitoring | |
| Web UI | |
| React Frontend | |
| Responsive Design | |
| Multi-Language Support | |
| Russian Localization | |
| Chinese Localization | |
| Spanish Localization | |
| Multi-Language Documentation | |
| Global Accessibility | |
| WAF Bypass | 15+ payloads |
| External Dependencies | 0 |
| Python Version | 3.8+ |
| Code Quality | Production-ready |
| ML Ready | |
| Confidence Scoring | |
| Modern XSS Support | |
| WebSocket XSS | |
| Service Worker XSS | |
| WebRTC XSS | |
| GraphQL XSS | |
| Shadow DOM XSS | |
| Custom Elements XSS | |
| Payload Testing API | |
| WAF Bypass Detection | |
| CLI Tool | |
| Export Capabilities | |

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
| **Version** | 2.0.0 |

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
