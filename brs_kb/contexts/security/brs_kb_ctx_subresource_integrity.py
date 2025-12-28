#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Subresource Integrity Bypass XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Subresource Integrity Bypass",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-693"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "sri", "integrity", "bypass", "security"],
    "description": """
Subresource Integrity (SRI) verifies resource integrity. XSS vulnerabilities occur when
SRI is bypassed, misconfigured, or when user input controls integrity hashes or resource URLs.

SEVERITY: HIGH
Bypassing SRI allows loading malicious resources, leading to XSS and code injection.
""",
    "attack_vector": """
SRI HASH BYPASS:
<script src="https://example.com/script.js" integrity="${userInput}"></script>
// XSS if hash is controlled or empty

SRI HASH COLLISION:
<script src="https://evil.com/xss.js" integrity="sha384-${userInput}"></script>
// XSS if hash collision is found

SRI MULTIPLE HASHES:
<script src="https://example.com/script.js" integrity="sha384-valid sha384-${userInput}"></script>
// XSS if browser accepts any valid hash

SRI CROSSORIGIN BYPASS:
<script src="https://evil.com/xss.js" integrity="sha384-..." crossorigin="anonymous"></script>
// XSS if crossorigin allows loading

SRI DYNAMIC CREATION:
const script = document.createElement('script');
script.src = userInput;
script.integrity = userInputHash;  // XSS if hash is controlled
document.head.appendChild(script);

SRI WITH CSP BYPASS:
// If CSP allows 'unsafe-inline', SRI can be bypassed
<script integrity="sha384-...">eval(userInput)</script>
""",
    "remediation": """
DEFENSE:

1. Always use SRI for external resources
2. Validate integrity hashes (whitelist allowed hashes)
3. Use crossorigin="anonymous" for cross-origin resources
4. Implement strict CSP
5. Validate resource URLs

SAFE PATTERN:
const allowedHashes = {
  'https://cdn.example.com/script.js': 'sha384-abc123...',
  'https://cdn.example.com/style.css': 'sha384-def456...'
};
function createScript(url) {
  const hash = allowedHashes[url];
  if (!hash) {
    throw new Error('Resource not allowed');
  }
  const script = document.createElement('script');
  script.src = url;
  script.integrity = hash;
  script.crossOrigin = 'anonymous';
  return script;
}

VALIDATION:
function validateIntegrity(hash) {
  if (!/^sha(256|384|512)-[A-Za-z0-9+/=]+$/.test(hash)) {
    throw new Error('Invalid integrity hash');
  }
  return hash;
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-693: Protection Mechanism Failure
- Subresource Integrity Specification
""",
}
