#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Permissions Policy XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Permissions Policy Bypass",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79", "CWE-693"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "permissions-policy", "feature-policy", "security", "bypass"],
    "description": """
Permissions Policy (formerly Feature Policy) controls browser features. XSS vulnerabilities
occur when Permissions Policy is misconfigured, allowing dangerous features, or when user
input controls policy values.

SEVERITY: HIGH
Bypassing Permissions Policy can enable dangerous APIs (camera, microphone, geolocation, etc.)
and lead to privacy violations and XSS.
""",
    "attack_vector": """
PERMISSIONS POLICY BYPASS:
Permissions-Policy: camera=*, microphone=*, geolocation=*
// Allows all origins, enabling XSS via media APIs

PERMISSIONS POLICY INJECTION:
Permissions-Policy: ${userInput}
// XSS if userInput contains malicious policy values

PERMISSIONS POLICY IFRAME:
<iframe allow="camera; microphone; geolocation" src="${userInput}"></iframe>
// XSS if src is data: URL

PERMISSIONS POLICY ALLOW ATTRIBUTE:
<iframe allow="${userInput}" src="https://example.com"></iframe>
// XSS if allow contains malicious features

PERMISSIONS POLICY WITH EVAL:
Permissions-Policy: eval=*
// Enables eval(), allowing XSS

PERMISSIONS POLICY EXECUTION-WHILE-NOT-RENDERED:
Permissions-Policy: execution-while-not-rendered=*
// Can bypass some XSS protections
""",
    "remediation": """
DEFENSE:

1. Restrict Permissions Policy to specific origins only
2. Use 'self' instead of '*' for same-origin features
3. Validate all policy values
4. Block dangerous features (eval, execution-while-not-rendered)
5. Implement strict CSP alongside Permissions Policy

SAFE PATTERN:
Permissions-Policy: camera='self', microphone='self', geolocation='self'
// Restrict to same origin only

VALIDATION:
const allowedFeatures = ['camera', 'microphone', 'geolocation'];
const allowedOrigins = ['self', 'https://trusted.com'];
function validatePolicy(feature, origin) {
  if (!allowedFeatures.includes(feature)) {
    throw new Error('Feature not allowed');
  }
  if (!allowedOrigins.includes(origin)) {
    throw new Error('Origin not allowed');
  }
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-693: Protection Mechanism Failure
- Permissions Policy Specification
""",
}
