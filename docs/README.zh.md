# BRS-KB

### XSS 

****

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/EPTLLC/BRS-KB)
[![Code Size](https://img.shields.io/badge/code-16.5k%20lines-brightgreen.svg)]()
[![Contexts](https://img.shields.io/badge/contexts-27-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-passing-success.svg)]()

XSS

[](#-) • [](#-) • [](#-) • [API](#-api-) • [](#-) • [](#-)

---

## BRS-KB

| | |
|---------|-------------|
| **27 ** | XSS |
| **** | |
| ** API** | Python |
| **** | Python 3.8+ |
| **SIEM ** | CVSS CWE/OWASP |
| **** | MIT |
| **** | |

## 

```bash
pip install brs-kb
```

****
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
pip install -e .
```

**** Python 3.8+ • 

## 

```python
from brs_kb import get_vulnerability_details, list_contexts

# XSS 
details = get_vulnerability_details('html_content')

print(details['title']) # Cross-Site Scripting (XSS) in HTML Content
print(details['severity']) # critical
print(details['cvss_score']) # 8.8
print(details['cwe']) # ['CWE-79']
print(details['owasp']) # ['A03:2021']

# 
contexts = list_contexts()
# ['css_context', 'default', 'dom_xss', 'html_attribute', ...]
```

## 

<details>
<summary><b>27 XSS </b></summary>

### HTML 
| | | | |
|---------|-------------|-------|----------|
| `html_content` | HTML XSS | 398 | |
| `html_attribute` | HTML XSS | 529 | |
| `html_comment` | HTML XSS | 68 | |

### JavaScript 
| | | | |
|---------|-------------|-------|----------|
| `javascript_context` | JavaScript | 636 | |
| `js_string` | JavaScript | 619 | |
| `js_object` | JavaScript | 619 | |

### 
| | | | |
|---------|-------------|-------|----------|
| `css_context` | CSS | 675 | |
| `svg_context` | SVG XSS | 288 | |
| `markdown_context` | Markdown XSS | 101 | |

### 
| | | | |
|---------|-------------|-------|----------|
| `json_value` | JSON XSS | 72 | |
| `xml_content` | XML/XHTML XSS | 81 | |

### 
| | | | |
|---------|-------------|-------|----------|
| `url_context` | URL/ XSS | 545 | |
| `dom_xss` | DOM XSS | 350 | |
| `template_injection` | | 107 | |
| `postmessage_xss` | PostMessage API | 125 | |
| `wasm_context` | WebAssembly XSS | 110 | |

### Web 
| | | | |
|---------|-------------|-------|----------|
| `websocket_xss` | WebSocket XSS | 407 | |
| `service_worker_xss` | Service Worker | 398 | |
| `webrtc_xss` | WebRTC P2P XSS | 420 | |
| `indexeddb_xss` | IndexedDB XSS | 378 | |
| `webgl_xss` | WebGL | 395 | |
| `shadow_dom_xss` | Shadow DOM | 385 | |
| `custom_elements_xss` | XSS | 390 | |
| `http2_push_xss` | HTTP/2 XSS | 375 | |
| `graphql_xss` | GraphQL API | 390 | |
| `iframe_sandbox_xss` | iframe | 380 | |

### 
| | | | |
|---------|-------------|-------|----------|
| `default` | XSS | 156 | - |

</details>

## 

### 


```python
{
 # 
 "title": "Cross-Site Scripting (XSS) in HTML Content",
 "description": "...",
 "attack_vector": "...",
 "remediation": "...",

 # 
 "severity": "critical", # low | medium | high | critical
 "cvss_score": 8.8, # CVSS 3.1 
 "cvss_vector": "CVSS:3.1/...", # CVSS 
 "reliability": "certain", # tentative | firm | certain
 "cwe": ["CWE-79"], # CWE 
 "owasp": ["A03:2021"], # OWASP Top 10 
 "tags": ["xss", "html", "reflected"] # 
}
```

### 

 payloads 

```python
from brs_kb.reverse_map import find_contexts_for_payload, get_defenses_for_context

# Payload → Context 
info = find_contexts_for_payload("<script>alert(1)</script>")
# → {'contexts': ['html_content', 'html_comment', 'svg_context'],
# 'severity': 'critical',
# 'defenses': ['html_encoding', 'csp', 'sanitization']}

# Context → Defense 
defenses = get_defenses_for_context('html_content')
# → [{'defense': 'html_encoding', 'priority': 1, 'required': True},
# {'defense': 'csp', 'priority': 1, 'required': True}, ...]
```

## CLI 

BRS-KB 

```bash
# 
pip install brs-kb

# 
brs-kb --help

# 
brs-kb info

# XSS 
brs-kb list-contexts

# 
brs-kb get-context websocket_xss

# payload
brs-kb analyze-payload "<script>alert(1)</script>"

# payloads
brs-kb search-payloads websocket --limit 5

# payload 
brs-kb test-payload "<script>alert(1)</script>" html_content

# 
brs-kb generate-report

# 
brs-kb validate

# 
brs-kb export contexts --format json --output contexts.json
```

****
- `info` - 
- `list-contexts` - XSS 
- `get-context <name>` - 
- `analyze-payload <payload>` - payload
- `search-payloads <query>` - payload 
- `test-payload <payload> <context>` - payload 
- `generate-report` - 
- `validate` - payload 
- `export <type> --format <format>` - payloadscontextsreports

## 

BRS-KB 

### Burp Suite 
- XSS payload 
- 
- 27 XSS 
- 

**** `plugins/burp_suite/BRSKBExtension.java` Burp 

### OWASP ZAP 
- BRS-KB intelligence XSS 
- payload 
- WAF 
- 

**** ZAP `plugins/owasp_zap/brs_kb_zap.py`

### Nuclei 
- 200+ XSS payloads
- 27 XSS 
- WAF 
- Web 

**** Nuclei 

 [plugins/README.md](plugins/README.md) 

## SIEM 

BRS-KB SIEM 

#### Splunk 
- XSS 
- XSS 
- 
- 

**** `siem_connectors/splunk/brs_kb_app.tar.gz` Splunk apps 

#### Elasticsearch 
- BRS-KB Logstash/Beats 
- XSS Kibana 
- 
- Elasticsearch Watcher 

**** `siem_connectors/elastic/` Logstash 

#### Graylog 
- GELF 
- 
- 
- XSS 

**** `siem_connectors/graylog/` 

 [siem_connectors/README.md](siem_connectors/README.md) 

## CI/CD 

BRS-KB CI/CD 

### GitLab CI (`.gitlab-ci.yml`)
- Python 3.8-3.12
- 
- PyPI 
- 

### GitLab CI (`.gitlab-ci.yml`) - 
- Python 
- 
- GitLab Pages
- 

### Jenkins (`Jenkinsfile`)
- 
- 
- 
- 

### (`scripts/setup_cicd.py`)
 CI/CD 

****
```bash
python3 scripts/setup_cicd.py
```

 [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) CI/CD 

## 

 [examples/](examples/) 

| | |
|---------|-------------|
| [`basic_usage.py`](examples/basic_usage.py) | API |
| [`scanner_integration.py`](examples/scanner_integration.py) | |
| [`siem_integration.py`](examples/siem_integration.py) | SIEM/SOC |
| [`reverse_mapping.py`](examples/reverse_mapping.py) | ML-ready |
| [`payload_database.py`](examples/payload_database.py) | 200+ payload API |
| [`cli_demo.py`](examples/cli_demo.py) | |
| [`plugin_demo.py`](examples/plugin_demo.py) | |
| [`siem_integration.py`](examples/siem_integration.py) | SIEM |
| [`cicd_demo.py`](examples/cicd_demo.py) | CI/CD |
| [`multilanguage_demo.py`](examples/multilanguage_demo.py) | |
| [`integrated_demo.py`](examples/integrated_demo.py) | |

****
```bash
# Python 
python3 examples/basic_usage.py
python3 examples/scanner_integration.py
python3 examples/cli_demo.py
python3 examples/plugin_demo.py
python3 examples/integrated_demo.py

# CLI 
brs-kb info # 
brs-kb list-contexts # XSS 
brs-kb analyze-payload "<script>alert(1)</script>" # payload 
brs-kb search-payloads websocket # payloads
brs-kb generate-report # 

# 
nuclei -t plugins/nuclei/templates/brs-kb-xss.yaml -u https://target.com

# SIEM 
python3 siem_connectors/splunk/brs_kb_splunk_connector.py --api-key YOUR_KEY --splunk-url https://splunk.company.com:8088

# CI/CD 
python3 scripts/setup_cicd.py

# 
brs-kb language ru
brs-kb language --list
```

## API 

### 

#### `get_vulnerability_details(context: str) -> Dict[str, Any]`


```python
details = get_vulnerability_details('html_content')
```

#### `list_contexts() -> List[str]`


```python
contexts = list_contexts() # ['css_context', 'default', 'dom_xss', ...]
```

#### `get_kb_info() -> Dict[str, Any]`


```python
info = get_kb_info()
print(f"Version: {info['version']}, Total contexts: {info['total_contexts']}")
```

#### `get_kb_version() -> str`


```python
version = get_kb_version() # "2.0.0"
```

### 

 `brs_kb.reverse_map`

#### `find_contexts_for_payload(payload: str) -> Dict`
 payload 

#### `predict_contexts_ml_ready(payload: str) -> Dict`
 ML-ready 

#### `get_defenses_for_context(context: str) -> List[Dict]`


#### `get_defense_info(defense: str) -> Dict`


#### `analyze_payload_with_patterns(payload: str) -> List[Tuple]`
 payload

#### `get_reverse_map_info() -> Dict`


#### `reverse_lookup(query_type: str, query: str) -> Dict`
 payloadcontextdefense pattern 

### Payload 

#### `get_payloads_by_context(context: str) -> List[Dict]`
 payloads

#### `get_payloads_by_severity(severity: str) -> List[Dict]`
 payloads

#### `search_payloads(query: str) -> List[Dict]`
 payloads 

#### `test_payload_in_context(payload: str, context: str) -> Dict`
 payload 

#### `get_database_info() -> Dict`
 payload 

### CLI 

#### `get_cli() -> BRSKBCLI`
 CLI 

**CLI **
- `brs-kb info` - 
- `brs-kb list-contexts` - XSS 
- `brs-kb get-context <name>` - 
- `brs-kb analyze-payload <payload>` - payload 
- `brs-kb search-payloads <query>` - payloads
- `brs-kb test-payload <payload> <context>` - 
- `brs-kb generate-report` - 
- `brs-kb validate` - 
- `brs-kb export <type>` - 

## 


### 

- XSS 
- 
- 
- 
- 

****
```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
git checkout -b feature/new-context
# 
pytest tests/ -v
git commit -m "Add: New context for WebSocket XSS"
git push origin feature/new-context
# Pull Request
```

 [CONTRIBUTING.md](CONTRIBUTING.md) 

## 

```
BRS-KB/
 brs_kb/ # 
 __init__.py # API
 schema.json # JSON Schema 
 reverse_map.py # 
 i18n.py # 
 cli.py # 
 payload_testing.py # Payload 
 payloads_db.py # Payload 
 contexts/ # 27 
 html_content.py
 javascript_context.py
 websocket_xss.py
 ...
 examples/ # 
 tests/ # (pytest)
 docs/ # 
 i18n/locales/ # 
 plugins/ # 
 siem_connectors/ # SIEM 
 web_ui/ # React Web 
 LICENSE # MIT 
 CONTRIBUTING.md # 
 CHANGELOG.md # 
 README.md # 
```

## 

```bash
# 
pytest tests/ -v

# pytest-cov
pytest tests/ -v --cov=brs_kb

# 
pytest tests/test_basic.py -v
```

## 

| | |
|--------|-------|
| | ~16,500+ |
| | 27 |
| Payload | 200+ |
| | 29 |
| | 27 |
| | 418 |
| | 33 |
| CLI | 9 |
| | 3 |
| SIEM | 3 |
| CI/CD | GitLab CI, Jenkins |
| | |
| Docker | |
| Kubernetes | |
| | |
| | |
| | |
| | |
| | |
| | 0 |
| Python | 3.8+ |
| | |
| ML | |
| | |
| XSS | |
| WebSocket XSS | |
| Service Worker XSS | |
| WebRTC XSS | |
| GraphQL XSS | |
| Shadow DOM XSS | |
| XSS | |
| Payload API | |
| WAF | |
| CLI | |
| | |
| | |
| Burp Suite | |
| OWASP ZAP | |
| Nuclei | |
| SIEM | |
| Splunk | |
| Elasticsearch | |
| Graylog | |
| CI/CD | |
| GitLab CI | |
| Jenkins | |
| | |
| | |
| | |
| | |

## 

**MIT ** - 

```
 (c) 2025 EasyProTech LLC / Brabus

“”
/
...
```

 [LICENSE](LICENSE) 

## 

| | |
|---|---|
| **** | BRS-KB (BRS XSS Knowledge Base) |
| **** | EasyProTech LLC |
| **** | [www.easypro.tech](https://www.easypro.tech) |
| **** | Brabus |
| **** | [https://t.me/easyprotech](https://t.me/easyprotech) |
| **** | [https://github.com/EPTLLC/BRS-KB](https://github.com/EPTLLC/BRS-KB) |
| **** | MIT |
| **** | Production-Ready |
| **** | 2.0.0 |

## 

- **[BRS-XSS](https://github.com/EPTLLC/brs-xss)** - Advanced XSS Scanner ( BRS-KB)

## 

****


- GitHub Issues 
- Pull Requests 
- SLA 


## 

- 
- 
- 

---

<div align="center">

** XSS **

*MIT • Python 3.8+ • *

[GitHub ](https://github.com/EPTLLC/BRS-KB) • [](https://github.com/EPTLLC/BRS-KB/issues) • [](https://github.com/EPTLLC/BRS-KB/issues)

</div>
