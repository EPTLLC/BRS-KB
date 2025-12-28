#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Speculation Rules API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Speculation Rules API",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "medium",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "speculation-rules", "prefetch", "prerender", "chrome-109"],
    "description": """
Speculation Rules API (Chrome 109+) enables prefetching and prerendering. XSS vulnerabilities
occur when user input controls speculation rule URLs or rule definitions without validation.

SEVERITY: MEDIUM
Can lead to XSS when prefetched/prerendered content contains user-controlled data.
""",
    "attack_vector": """
SPECULATION RULES URL INJECTION:
<script type="speculationrules">
{
  "prefetch": [{
    "source": "list",
    "urls": [userInput]  // XSS if URL is javascript: or data:
  }]
}
</script>

SPECULATION RULES PRERENDER:
<script type="speculationrules">
{
  "prerender": [{
    "source": "list",
    "urls": [userInput]  // XSS if URL contains malicious content
  }]
}
</script>

SPECULATION RULES EAGER:
<script type="speculationrules">
{
  "prefetch": [{
    "source": "list",
    "urls": [userInput],
    "eager": true  // XSS if eager loads malicious content
  }]
}
</script>

SPECULATION RULES REFERRER POLICY:
<script type="speculationrules">
{
  "prefetch": [{
    "source": "list",
    "urls": [userInput],
    "referrer_policy": userInput  // XSS if policy is controlled
  }]
}
</script>

SPECULATION RULES EXPECTS:
<script type="speculationrules">
{
  "prerender": [{
    "source": "list",
    "urls": [userInput],
    "expects": userInput  // XSS if expects is controlled
  }]
}
</script>
""",
    "remediation": """
DEFENSE:

1. Validate all speculation rule URLs (whitelist HTTPS only)
2. Block javascript: and data: URLs
3. Validate rule structure
4. Implement CSP
5. Restrict speculation rules to trusted origins

SAFE PATTERN:
function validateSpeculationUrl(url) {
  if (!url.startsWith('https://')) {
    throw new Error('Only HTTPS URLs allowed');
  }
  if (url.startsWith('javascript:') || url.startsWith('data:')) {
    throw new Error('Invalid URL');
  }
  return url;
}
<script type="speculationrules">
{
  "prefetch": [{
    "source": "list",
    "urls": [validateSpeculationUrl(userInput)]
  }]
}
</script>

VALIDATION:
const allowedOrigins = ['https://example.com', 'https://cdn.example.com'];
function validateUrl(url) {
  if (!allowedOrigins.some(origin => url.startsWith(origin))) {
    throw new Error('URL not allowed');
  }
  return url;
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Speculation Rules API Specification
""",
}
