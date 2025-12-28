#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Web Share API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Web Share API",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "web-share", "native-share", "mobile", "chrome-89"],
    "description": """
Web Share API (Chrome 89+) allows web apps to use native sharing. XSS vulnerabilities occur
when user input controls share data (title, text, URL) without validation, leading to
XSS when shared content is rendered.

SEVERITY: MEDIUM
Can lead to XSS when shared content is opened in vulnerable applications or browsers.
""",
    "attack_vector": """
WEB SHARE TITLE INJECTION:
await navigator.share({
  title: userInput,  // XSS if title contains HTML
  text: 'Content',
  url: 'https://example.com'
});

WEB SHARE TEXT INJECTION:
await navigator.share({
  title: 'Title',
  text: userInput,  // XSS if text contains HTML
  url: 'https://example.com'
});

WEB SHARE URL INJECTION:
await navigator.share({
  title: 'Title',
  text: 'Content',
  url: userInput  // XSS if URL is javascript: or data:
});

WEB SHARE FILES:
await navigator.share({
  title: 'Title',
  files: [new File([userInput], 'file.html')]  // XSS if file contains HTML
});

WEB SHARE WITH EVAL:
await navigator.share({
  title: 'Title',
  text: 'Content',
  url: `javascript:eval('${userInput}')`  // XSS
});
""",
    "remediation": """
DEFENSE:

1. Sanitize all share data (title, text, URL)
2. Validate URLs (block javascript: and data:)
3. Validate file types and content
4. Use textContent for share text
5. Implement URL validation

SAFE PATTERN:
function sanitizeShareData(data) {
  return {
    title: DOMPurify.sanitize(data.title),
    text: DOMPurify.sanitize(data.text),
    url: validateUrl(data.url)
  };
}
await navigator.share(sanitizeShareData({ title: userInput, text: 'Content', url: 'https://example.com' }));

URL VALIDATION:
function validateUrl(url) {
  if (url.startsWith('javascript:') || url.startsWith('data:')) {
    throw new Error('Invalid URL');
  }
  if (!url.startsWith('https://')) {
    throw new Error('Only HTTPS URLs allowed');
  }
  return url;
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Web Share API Specification
""",
}
