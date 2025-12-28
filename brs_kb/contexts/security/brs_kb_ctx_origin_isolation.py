#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Origin Isolation XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Origin Isolation Bypass",
    "severity": "high",
    "cvss_score": 7.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "medium",
    "cwe": ["CWE-79", "CWE-693"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "origin-isolation", "cross-origin", "spectre", "security"],
    "description": """
Origin Isolation headers isolate origins to prevent Spectre attacks. XSS vulnerabilities
occur when origin isolation is misconfigured or bypassed, allowing cross-origin attacks
or SharedArrayBuffer access.

SEVERITY: HIGH
Bypassing origin isolation can enable Spectre attacks, SharedArrayBuffer access, and
cross-origin data exfiltration.
""",
    "attack_vector": """
ORIGIN ISOLATION BYPASS:
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
// If misconfigured, can allow cross-origin access

ORIGIN ISOLATION WITH SHAREDARRAYBUFFER:
// Without proper headers, SharedArrayBuffer can be accessed
const buffer = new SharedArrayBuffer(1024);
postMessage(buffer, '*');  // Leak to other origins

ORIGIN ISOLATION IFRAME:
<iframe src="${userInput}" allow="cross-origin-isolated"></iframe>
// XSS if src is controlled

ORIGIN ISOLATION WORKER:
const worker = new Worker(userInput);  // XSS if URL is data:
worker.postMessage(sensitiveData);

ORIGIN ISOLATION POSTMESSAGE:
window.postMessage(sensitiveData, '*');  // Leak if isolation is bypassed
""",
    "remediation": """
DEFENSE:

1. Always use both COOP and COEP headers together
2. Validate all cross-origin communication
3. Restrict SharedArrayBuffer to isolated origins only
4. Use specific target origins in postMessage
5. Implement strict CSP

REQUIRED HEADERS:
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp

SAFE PATTERN:
// Check if origin is isolated
if (self.crossOriginIsolated) {
  // Safe to use SharedArrayBuffer
  const buffer = new SharedArrayBuffer(1024);
} else {
  throw new Error('Origin not isolated');
}

POSTMESSAGE VALIDATION:
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://trusted.com') {
    return;  // Ignore untrusted origins
  }
  // Process message
});

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-693: Protection Mechanism Failure
- Origin Isolation Specification
- Spectre Mitigation
""",
}
