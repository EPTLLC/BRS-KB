#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Top-Level Await XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Top-Level Await",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "es2022", "top-level-await", "async", "modules"],
    "description": """
Top-Level Await (ES2022) allows await at module top level. XSS vulnerabilities occur
when user input is used in dynamic imports or fetch calls within top-level await expressions.

SEVERITY: HIGH
Modern ES feature with growing adoption. Can bypass some async execution restrictions.
""",
    "attack_vector": """
TOP-LEVEL AWAIT WITH DYNAMIC IMPORT:
<script type="module">
const data = await fetch('/api/data').then(r => r.json());
await import(data.moduleUrl);  // XSS if moduleUrl is user-controlled
</script>

TOP-LEVEL AWAIT WITH FETCH:
<script type="module">
const response = await fetch(userInput);  // XSS if userInput is data: URL
const text = await response.text();
eval(text);
</script>

TOP-LEVEL AWAIT WITH EVAL:
<script type="module">
const code = await fetch('/user-content').then(r => r.text());
eval(code);  // XSS if code contains user input
</script>

TOP-LEVEL AWAIT WITH INNERHTML:
<script type="module">
const html = await fetch('/api/html').then(r => r.text());
document.body.innerHTML = html;  // XSS
</script>

TOP-LEVEL AWAIT WITH FUNCTION:
<script type="module">
const fn = await import(`data:text/javascript,${userInput}`);
fn.default();
</script>
""",
    "remediation": """
DEFENSE:

1. Validate all URLs used in dynamic imports
2. Sanitize content before innerHTML assignment
3. Avoid eval() with user input
4. Use textContent instead of innerHTML
5. Implement CSP with strict module-src

SAFE PATTERN:
<script type="module">
const data = await fetch('/api/data').then(r => r.json());
const sanitizedUrl = validateModuleUrl(data.moduleUrl);
await import(sanitizedUrl);
</script>

CONTENT SANITIZATION:
const html = await fetch('/api/html').then(r => r.text());
element.innerHTML = DOMPurify.sanitize(html);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- ES2022 Specification
""",
}
