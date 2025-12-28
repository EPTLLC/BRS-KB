# BRS-KB

Deterministic, context-aware XSS payload intelligence for scanners, CI/CD and security tooling.

Python 3.8+. MIT License.

## Install

```bash
pip install brs-kb
```

## API

```
Base URL: https://brs-kb.easypro.tech/api/v1
API Key:  BRS-KB_free_kUOgkmm2lxr2sgIg_hFsmuBsFGB4fVpakvu0pzANStRIpeGs8
# Public read-only key for testing and CI/CD
```

```bash
curl -H "X-API-Key: BRS-KB_free_kUOgkmm2lxr2sgIg_hFsmuBsFGB4fVpakvu0pzANStRIpeGs8" \
  https://brs-kb.easypro.tech/api/v1/payloads?context=javascript&limit=10
```

Endpoints: `/health`, `/info`, `/contexts`, `/contexts/{id}`, `/payloads`, `/payloads/search`, `/analyze`, `/defenses`, `/stats`

Docs: https://brs-kb.easypro.tech/docs.html

## Python

```python
from brs_kb import get_vulnerability_details, list_contexts, search_payloads, get_waf_bypass_payloads

# 151 contexts
contexts = list_contexts()

# Context details with CVSS
details = get_vulnerability_details('javascript')
# {'severity': 'critical', 'cvss_score': 9.0, 'cwe': ['CWE-79'], ...}

# Search
results = search_payloads('websocket')

# WAF bypasses
waf = get_waf_bypass_payloads()  # 1300+
```

## CLI

```bash
brs-kb info
brs-kb list-contexts
brs-kb get-context javascript
brs-kb analyze-payload "<script>alert(1)</script>"
brs-kb search-payloads "cloudflare"
brs-kb export payloads --format json
brs-kb serve --port 8080
```

## CI/CD

```yaml
# GitHub Actions
- name: Install BRS-KB
  run: pip install brs-kb

- name: Validate
  run: brs-kb info && python -c "from brs_kb import list_contexts; assert len(list_contexts()) > 100"
```

```bash
# Docker
docker pull ghcr.io/eptllc/brs-kb:latest
docker run -p 8080:8080 ghcr.io/eptllc/brs-kb:latest
```

## Dataset

- 4,200+ payloads
- 151 contexts
- 1,300+ WAF bypasses
- CVSS scores
- Browser compatibility
- Encoding metadata

## Integration

Native knowledge backend for [BRS-XSS](https://github.com/EPTLLC/brs-xss).

```bash
pip install brs-kb brs-xss
```

SIEM connectors: `siem_connectors/` (Splunk, Elasticsearch, Graylog)

## Test

```bash
pytest tests/ -v
```

## License

MIT

## Links

- https://brs-kb.easypro.tech
- https://github.com/EPTLLC/BRS-KB
- https://github.com/EPTLLC/brs-xss
