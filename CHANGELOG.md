# Changelog

All notable changes to BRS-KB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2025-12-28

### Initial Public Release

First stable release of BRS-KB.

** Public API:** [brs-kb.easypro.tech](https://brs-kb.easypro.tech)

### Features

- **4,200+ XSS Payloads** — unique, deduplicated, with full metadata
- **151 XSS Contexts** — full coverage across all attack vectors
- **WAF Bypass Database** — 1,300+ techniques for Cloudflare, Akamai, AWS WAF, Imperva, ModSecurity
- **REST API** — full-featured HTTP API with 13 endpoints
- **CLI Tool** — 12 commands for command-line usage
- **Zero Dependencies** — pure Python 3.8+

### Payload Categories

| Category | Count | Description |
|----------|-------|-------------|
| Core | 200+ | Essential XSS vectors |
| WAF Bypass | 1,300+ | All major WAFs |
| Modern Browser | 200+ | ES6+, WebAssembly, Service Workers |
| Context-Specific | 800+ | DOM, Template, GraphQL, WebSocket, SSE |
| Exotic | 200+ | mXSS, DOM Clobbering, Prototype Pollution |
| Frameworks | 300+ | React, Vue, Angular, Svelte, HTMX, Alpine |
| Event Handlers | 105 | All HTML event handlers |
| Obfuscation | 100+ | Encoding, charcode, JSFuck |

### Context Categories

| Category | Contexts | Description |
|----------|----------|-------------|
| HTML | 15 | HTML injection contexts |
| JavaScript | 15 | JS execution contexts |
| DOM | 15 | DOM-based XSS |
| Frameworks | 25 | Framework-specific |
| API | 20 | API/Realtime contexts |
| Browser | 20 | Browser API contexts |
| Security | 15 | Security bypass contexts |
| Injection | 12 | Various injection types |
| Other | 14 | Specialized contexts |

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/info` | System information |
| `GET /api/health` | Health check |
| `GET /api/contexts` | List all contexts |
| `GET /api/contexts/{id}` | Context details |
| `GET /api/payloads` | List payloads |
| `GET /api/payloads/search` | Search payloads |
| `POST /api/analyze` | Analyze payload |
| `GET /api/defenses` | Get defenses |
| `GET /api/stats` | Statistics |

### Infrastructure

- Modern build system with Hatch (PEP 621)
- GitHub Actions CI/CD pipeline
- Multi-Python version support (3.8-3.13)
- Type hints with `py.typed` marker
- 81% test coverage (334 tests)
- Docker and Kubernetes configurations
- Prometheus metrics integration

### Integrations

- **BRS-XSS Scanner** — seamless integration as payload source
- **Burp Suite** — plugin for real-time analysis
- **OWASP ZAP** — automated scanning plugin
- **Nuclei** — template-based testing
- **SIEM** — Splunk, Elasticsearch, Graylog connectors

---

**Project**: BRS-KB (BRS XSS Knowledge Base)  
**Company**: EasyProTech LLC (www.easypro.tech)  
**Developer**: Brabus  
**API**: https://brs-kb.easypro.tech  
**Telegram**: https://t.me/easyprotech  
**License**: MIT  
