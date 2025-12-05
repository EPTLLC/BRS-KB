# Changelog

All notable changes to BRS-KB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2025-12-05

### Added
- **REST API Server**: Full-featured HTTP API for Web UI integration
  - New `brs_kb/api_server.py` module with 13 REST endpoints
  - CORS support for cross-origin requests
  - Endpoints: `/api/info`, `/api/contexts`, `/api/payloads`, `/api/analyze`, etc.
  - JSON responses with proper error handling
  - CLI command `serve` for starting API server
  - Prometheus metrics server integration (`--metrics` flag)
  - Configurable port and host (`--port`, `--host` flags)
  - Public API exports: `start_api_server()`, `start_metrics_server()`
- **SQLite Database Support**: Migrated payload database from in-memory to SQLite
  - New `brs_kb/payloads_db_sqlite.py` module for SQLite operations
  - Database migrations system (`brs_kb/migrations.py`)
  - Automatic migration on first import
  - CLI command `migrate` for manual migration with `--force` option
  - Fallback to in-memory database if SQLite unavailable
  - Database location: `brs_kb/data/payloads.db`
- **Modular Architecture**: Refactored large files into smaller modules (<300 lines each)
  - `payloads_db.py` (2929 lines) → `brs_kb/payloads_db/` package (8 modules)
  - `reverse_map.py` (720 lines) → `brs_kb/reverse_map/` package (5 modules)
  - `cli.py` (577 lines) → `brs_kb/cli/` package (16 modules)
  - All modules maintain backward compatibility through wrapper files
- **CLI Improvements**:
  - New `serve` command for API server (`brs-kb serve --port 8080`)
  - New `migrate` command for database migration
  - New `language` command for language management
  - Command pattern architecture for better maintainability
  - `__main__.py` entry point for module execution
  - Total of 12 CLI commands (was 9 in v2.0.0)
- **Test Coverage Improvements**:
  - Increased test coverage from 33 to 334 tests (10x increase)
  - Added 18 tests for `metrics_server.py` (79% coverage)
  - Added 28 tests for `api_server.py` (full endpoint coverage)
  - Added tests for all `payloads_db/` submodules (100% coverage)
  - Added tests for `reverse_map/utils.py` (96% coverage)
  - Added tests for SQLite database module
  - Overall coverage increased to 81%
- **Web UI Integration**: Complete React frontend with API integration
  - API service layer (`web_ui/src/services/api.js`)
  - New Payloads page with search and filtering
  - Interactive Playground for payload analysis
  - Dashboard with statistics and charts
  - API Documentation page
  - Updated Contexts page with real API calls
  - Fallback to cached data when API unavailable
- **Infrastructure**:
  - Custom exceptions module (`brs_kb/exceptions.py`)
  - Structured JSON logging (`brs_kb/logger.py`)
  - Input validation module (`brs_kb/validation.py`)
  - Prometheus metrics module (`brs_kb/metrics.py`)
  - Payload indexing system (`brs_kb/payload_index.py`)

### Changed
- Version updated from 2.0.0 to 3.0.0
- Database operations now prefer SQLite with automatic fallback
- CLI commands increased from 9 to 12
- Test count increased from 33 to 334
- Code coverage increased from ~30% to 81%

### Technical
- Added `brs_kb/api_server.py` with REST API server
- Added `brs_kb/metrics_server.py` for Prometheus metrics
- Added `brs_kb/cli/commands/serve.py` for API server command
- Added `web_ui/src/services/api.js` for frontend API client
- Added new pages: `Payloads.js`, `Playground.js`, `Dashboard.js`, `ApiDocs.js`
- Updated `Contexts.js` for API integration
- Module execution: `python3 -m brs_kb.cli <command>`

## [2.0.0] - 2025-11-03

### Added
- Web UI with React 18 for visual exploration and testing
- Browser extension (Chrome/Firefox) for real-time XSS detection
- Postman collection for API testing workflow
- Insomnia plugin for REST client integration
- Internationalization system with support for 4 languages (EN, RU, ZH, ES)
- GitHub Pages deployment configuration
- Docker and Kubernetes deployment configurations
- CI/CD pipelines for GitHub Actions, GitLab CI, and Jenkins
- Monitoring configuration with Prometheus and alerts
- SIEM connectors for Splunk, Elasticsearch, and Graylog

### Enhanced
- Professional documentation across all markdown files
- Improved API reference documentation
- Multi-language documentation structure (EN, RU, ZH, ES)
- Enhanced reverse mapping system with ML-ready features
- Payload database expanded to 200+ payloads
- Context coverage increased to 27 XSS contexts

### Changed
- Version updated from 1.1.0 to 2.0.0
- Documentation style changed to professional technical writing
- Removed emoji and marketing language from files
- Standardized code structure and organization

### Technical
- Added web_ui/ directory with React application
- Added browser_extension/ with manifest v3
- Added i18n/ directory with JSON locale files
- Test coverage: 33 tests
- CLI commands: 9 commands

## [1.1.0] - 2025-10-25

### Added
- Enhanced reverse mapping system with ML-ready architecture
- Confidence scoring for payload analysis
- 29 detection patterns for automatic context detection
- 10 new modern XSS contexts (WebSocket, Service Worker, WebRTC, GraphQL, etc.)
- Payload database with 200+ categorized entries
- Payload testing API for automated validation
- CLI tool with full-featured command-line interface
- Export capabilities in JSON and text formats
- Security scanner plugins (Burp Suite, OWASP ZAP, Nuclei)
- SIEM integration modules
- CI/CD configurations for multiple platforms
- Multi-language support infrastructure

### Enhanced
- Advanced reverse mapping system (v2.0)
- ML-ready payload analysis with confidence metrics
- Modern XSS support with comprehensive coverage
- Defense mapping with bypass difficulty ratings
- Test coverage expanded to 20 tests

### New Contexts
- websocket_xss (407 lines, High severity)
- service_worker_xss (398 lines, High severity)
- webrtc_xss (420 lines, High severity)
- indexeddb_xss (378 lines, Medium severity)
- webgl_xss (395 lines, Medium severity)
- shadow_dom_xss (385 lines, High severity)
- custom_elements_xss (390 lines, High severity)
- http2_push_xss (375 lines, Medium severity)
- graphql_xss (390 lines, High severity)
- iframe_sandbox_xss (380 lines, Medium severity)

### Technical
- Pattern database with 29 regex patterns
- Feature extraction with 10+ features for ML
- Analysis methods: pattern matching, legacy exact match, fallback modes
- Modern defenses: Trusted Types, CSP Nonce, WAF rules

## [1.0.0] - 2025-10-14

### Initial Release
- XSS knowledge base with 17 vulnerability contexts
- MIT License for maximum compatibility
- Modular architecture with dynamic context loading
- CVSS 3.1 scoring and severity classification
- CWE and OWASP Top 10 mappings
- JSON Schema validation
- Reverse mapping system (Payload to Context to Defense)
- Python package structure for PyPI distribution
- API for vulnerability details retrieval
- Community contribution guidelines
- Professional documentation

### Context Modules
- html_content, html_attribute, html_comment
- javascript_context, js_string, js_object
- css_context, svg_context, markdown_context
- json_value, xml_content, url_context
- dom_xss, template_injection, postmessage_xss
- wasm_context, default

---

**Project**: BRS-KB (BRS XSS Knowledge Base)
**Company**: EasyProTech LLC (www.easypro.tech)
**Developer**: Brabus
**Contact**: https://t.me/easyprotech
**License**: MIT
**Status**: Production-Ready
