# Contributing to BRS-KB

Thank you for contributing to BRS-KB. This is a community-driven XSS Knowledge Base.

## Ways to Contribute

1. **Submit payloads** — New XSS vectors and bypass techniques
2. **Add contexts** — New vulnerability contexts
3. **Report issues** — Bugs, errors, outdated information
4. **Improve docs** — Documentation and examples

## Quick Start

### Option 1: GitHub Discussions (Easiest)

Post your contribution in [GitHub Discussions](https://github.com/EPTLLC/BRS-KB/discussions):

- **Payload** — New XSS payload
- **Context** — New vulnerability context
- **WAF-bypass** — WAF evasion technique

We'll review and add it to the database.

### Option 2: Pull Request

```bash
git clone https://github.com/EPTLLC/BRS-KB.git
cd BRS-KB
git checkout -b feature/your-contribution
```

## Adding Payloads

Payloads are in `brs_kb/payloads_db/`. Create or update a file:

```python
from brs_kb.payloads_db.models import PayloadEntry, Encoding

YOUR_PAYLOADS = {
    "unique_id": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["html_body", "javascript"],
        tags=["basic", "script"],
        severity="high",
        cvss_score=6.1,
        description="Basic script injection",
        waf_evasion=False,
        encoding=Encoding.NONE,
    ),
}
```

### PayloadEntry Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `payload` | str | Yes | The XSS payload |
| `contexts` | list | Yes | Applicable contexts |
| `tags` | list | Yes | Descriptive tags |
| `severity` | str | Yes | low/medium/high/critical |
| `cvss_score` | float | No | CVSS score (0.0-10.0) |
| `description` | str | No | Payload description |
| `waf_evasion` | bool | No | WAF bypass payload |
| `encoding` | Encoding | No | Encoding type used |

### Encoding Types

```python
from brs_kb.payloads_db.models import Encoding

Encoding.NONE           # No encoding
Encoding.URL            # URL encoding
Encoding.DOUBLE_URL     # Double URL encoding
Encoding.UNICODE        # Unicode encoding
Encoding.HTML_ENTITIES  # HTML entity encoding
Encoding.BASE64         # Base64 encoding
Encoding.HEX            # Hex encoding
```

## Adding Contexts

Contexts are in `brs_kb/contexts/`. Create a new file:

```python
"""
BRS-KB Context: Your Context Name
"""

DETAILS = {
    "title": "XSS in Your Context",
    "severity": "high",
    "cvss_score": 7.5,
    "cwe": ["CWE-79"],
    "tags": ["xss", "your-context"],
    
    "description": """
    Description of the vulnerability context.
    When and where this occurs.
    """,
    
    "attack_vector": """
    Attack techniques and example payloads.
    """,
    
    "remediation": """
    How to fix and prevent this vulnerability.
    """,
}
```

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Check imports work
python -c "from brs_kb import get_kb_info; print(get_kb_info())"
```

## Pull Request Guidelines

1. One feature per PR
2. Clear commit messages
3. Test your changes
4. Update docs if needed

## Code Style

- Python 3.9+
- English only
- Clear variable names
- Comments for complex logic

## Community

- [GitHub Discussions](https://github.com/EPTLLC/BRS-KB/discussions)
- [Telegram](https://t.me/easyprotech)

## License

Contributions are licensed under MIT License.

---

**EasyProTech LLC** | [easypro.tech](https://easypro.tech)
