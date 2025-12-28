#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: WebTransport API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via WebTransport API",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "webtransport", "quic", "http3", "streaming", "chrome-97"],
    "description": """
WebTransport API (Chrome 97+) provides low-level access to HTTP/3 and QUIC. XSS vulnerabilities
occur when user input controls transport URLs, stream data, or datagram payloads without validation.

SEVERITY: HIGH
Low-level transport access can bypass same-origin policy and lead to data exfiltration.
""",
    "attack_vector": """
WEBTRANSPORT URL INJECTION:
const transport = new WebTransport(userInput);  // XSS if URL is data: or javascript:

WEBTRANSPORT STREAM DATA:
const transport = await new WebTransport('https://example.com');
const stream = await transport.createBidirectionalStream();
const writer = stream.writable.getWriter();
await writer.write(new TextEncoder().encode(userInput));  // XSS if data is malicious

WEBTRANSPORT DATAGRAM:
const transport = await new WebTransport('https://example.com');
const datagrams = transport.datagrams;
const writer = datagrams.writable.getWriter();
await writer.write(new TextEncoder().encode(userInput));  // XSS

WEBTRANSPORT READ STREAM:
const reader = stream.readable.getReader();
const { value } = await reader.read();
const text = new TextDecoder().decode(value);
document.body.innerHTML = text;  // XSS if value contains HTML

WEBTRANSPORT READ DATAGRAM:
const reader = datagrams.readable.getReader();
const { value } = await reader.read();
const text = new TextDecoder().decode(value);
eval(text);  // XSS if value is JavaScript
""",
    "remediation": """
DEFENSE:

1. Validate all WebTransport URLs (whitelist HTTPS only)
2. Sanitize stream data before rendering
3. Validate datagram payloads
4. Block data: and javascript: URLs
5. Implement CSP

SAFE PATTERN:
function validateWebTransportUrl(url) {
  if (!url.startsWith('https://')) {
    throw new Error('Only HTTPS URLs allowed');
  }
  // Additional validation
  return url;
}
const transport = await new WebTransport(validateWebTransportUrl(userInput));

DATA SANITIZATION:
const reader = stream.readable.getReader();
const { value } = await reader.read();
const text = new TextDecoder().decode(value);
element.textContent = text;  // Safe
// Or
element.innerHTML = DOMPurify.sanitize(text);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- WebTransport API Specification
- HTTP/3 Security Considerations
""",
}
