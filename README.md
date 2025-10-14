<div align="center">

# BRS-KB

### Community XSS Knowledge Base

**Open Knowledge for Security Community**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/easypro-tech/BRS-KB)
[![Code Size](https://img.shields.io/badge/code-5.9k%20lines-brightgreen.svg)]()
[![Contexts](https://img.shields.io/badge/contexts-17-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-passing-success.svg)]()

Comprehensive, community-driven knowledge base for Cross-Site Scripting (XSS) vulnerabilities

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [API](#-api-reference) • [Examples](#-examples) • [Contributing](#-contributing)

</div>

---

## Why BRS-KB?

| Feature | Description |
|---------|-------------|
| **17 Contexts** | Covering classic and modern XSS vulnerability types |
| **Detailed Info** | Attack vectors, bypass techniques, defense strategies |
| **Simple API** | Python library, easy to integrate |
| **Zero Dependencies** | Pure Python 3.8+ |
| **SIEM Compatible** | CVSS scores, CWE/OWASP mappings, severity levels |
| **Open Source** | MIT licensed, community contributions welcome |
| **In Production** | Used in security scanners and tools |

## Installation

```bash
pip install brs-kb
```

**From source:**
```bash
git clone https://github.com/easypro-tech/BRS-KB.git
cd BRS-KB
pip install -e .
```

**Requirements:** Python 3.8+ • No external dependencies

## Quick Start

```python
from brs_kb import get_vulnerability_details, list_contexts

# Get detailed XSS context information
details = get_vulnerability_details('html_content')

print(details['title'])        # Cross-Site Scripting (XSS) in HTML Content
print(details['severity'])     # critical
print(details['cvss_score'])   # 8.8
print(details['cwe'])          # ['CWE-79']
print(details['owasp'])        # ['A03:2021']

# List all available contexts
contexts = list_contexts()
# ['css_context', 'default', 'dom_xss', 'html_attribute', ...]
```

## Available Contexts

<details>
<summary><b>17 XSS Vulnerability Contexts</b> (click to expand)</summary>

### Core HTML Contexts
| Context | Description | Lines | Severity |
|---------|-------------|-------|----------|
| `html_content` | XSS in HTML body/content | 398 | Critical |
| `html_attribute` | XSS in HTML attributes | 529 | Critical |
| `html_comment` | XSS in HTML comments | 68 | Medium |

### JavaScript Contexts
| Context | Description | Lines | Severity |
|---------|-------------|-------|----------|
| `javascript_context` | Direct JavaScript injection | 636 | Critical |
| `js_string` | JavaScript string injection | 619 | Critical |
| `js_object` | JavaScript object injection | 619 | High |

### Style & Markup
| Context | Description | Lines | Severity |
|---------|-------------|-------|----------|
| `css_context` | CSS injection & style attrs | 675 | High |
| `svg_context` | SVG-based XSS vectors | 288 | High |
| `markdown_context` | Markdown rendering XSS | 101 | Medium |

### Data Formats
| Context | Description | Lines | Severity |
|---------|-------------|-------|----------|
| `json_value` | JSON context XSS | 72 | Medium |
| `xml_content` | XML/XHTML XSS vectors | 81 | High |

### Advanced Vectors
| Context | Description | Lines | Severity |
|---------|-------------|-------|----------|
| `url_context` | URL/protocol-based XSS | 545 | High |
| `dom_xss` | DOM-based XSS (client-side) | 350 | High |
| `template_injection` | Client-side template injection | 107 | Critical |
| `postmessage_xss` | PostMessage API vulnerabilities | 125 | High |
| `wasm_context` | WebAssembly context XSS | 110 | Medium |

### Fallback
| Context | Description | Lines | Severity |
|---------|-------------|-------|----------|
| `default` | Generic XSS information | 156 | - |

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
    "severity": "critical",           # low | medium | high | critical
    "cvss_score": 8.8,                # CVSS 3.1 base score
    "cvss_vector": "CVSS:3.1/...",    # Full CVSS vector string
    "reliability": "certain",         # tentative | firm | certain
    "cwe": ["CWE-79"],                # CWE identifiers
    "owasp": ["A03:2021"],            # OWASP Top 10 mapping
    "tags": ["xss", "html", "reflected"]  # Classification tags
}
```

### Reverse Mapping System

Map payloads to contexts and defenses:

```python
from brs_kb.reverse_map import find_contexts_for_payload, get_defenses_for_context

# Payload → Context mapping
info = find_contexts_for_payload("<script>alert(1)</script>")
# → {'contexts': ['html_content', 'html_comment', 'svg_context'],
#    'severity': 'critical',
#    'defenses': ['html_encoding', 'csp', 'sanitization']}

# Context → Defense mapping
defenses = get_defenses_for_context('html_content')
# → [{'defense': 'html_encoding', 'priority': 1, 'required': True},
#     {'defense': 'csp', 'priority': 1, 'required': True}, ...]
```

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

## Examples

See [examples/](examples/) directory for integration examples:

| Example | Description |
|---------|-------------|
| [`basic_usage.py`](examples/basic_usage.py) | Basic API usage and functionality |
| [`scanner_integration.py`](examples/scanner_integration.py) | Integration into security scanners |
| [`siem_integration.py`](examples/siem_integration.py) | SIEM/SOC threat intelligence |
| [`reverse_mapping.py`](examples/reverse_mapping.py) | Payload → Context → Defense mapping |

**Run examples:**
```bash
python3 examples/basic_usage.py
python3 examples/scanner_integration.py
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
contexts = list_contexts()  # ['css_context', 'default', 'dom_xss', ...]
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
version = get_kb_version()  # "1.0.0"
```

### Reverse Mapping Functions

Import from `brs_kb.reverse_map`:

#### `find_contexts_for_payload(payload: str) -> Dict`
Find contexts where payload is effective.

#### `get_defenses_for_context(context: str) -> List[Dict]`
Get recommended defenses for a context.

#### `get_defense_info(defense: str) -> Dict`
Get implementation details for a defense mechanism.

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
git clone https://github.com/YOUR-USERNAME/BRS-KB.git
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
├── brs_kb/                    # Main package
│   ├── __init__.py            # Core API
│   ├── schema.json            # JSON Schema validation
│   ├── reverse_map.py         # Reverse mapping system
│   └── contexts/              # 17 vulnerability contexts
│       ├── html_content.py
│       ├── dom_xss.py
│       ├── template_injection.py
│       └── ...
├── examples/                  # Integration examples
├── tests/                     # Test suite (pytest)
├── LICENSE                    # MIT License
├── CONTRIBUTING.md            # Contribution guide
├── CHANGELOG.md               # Version history
└── README.md                  # This file
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
| Total Lines | ~5,900+ |
| Context Modules | 17 |
| Average Module Size | 307 lines |
| Test Coverage | 14 tests |
| External Dependencies | 0 |
| Python Version | 3.8+ |
| Code Quality | Production-ready |

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
| **Repository** | [https://github.com/easypro-tech/BRS-KB](https://github.com/easypro-tech/BRS-KB) |
| **License** | MIT |
| **Status** | Production-Ready |
| **Version** | 1.0.0 |

## Related Projects

- **[BRS-XSS](https://github.com/easypro-tech/BRS-XSS)** - Advanced XSS Scanner (uses BRS-KB)

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

[Star on GitHub](https://github.com/easypro-tech/BRS-KB) • [Report Bug](https://github.com/easypro-tech/BRS-KB/issues) • [Request Feature](https://github.com/easypro-tech/BRS-KB/issues)

</div>
