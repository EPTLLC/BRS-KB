#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: SSE Handler XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via SSE Event Handlers",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "sse", "eventsource", "handler", "onopen", "onerror"],
    "description": """
SSE event handler XSS occurs when onopen, onerror, or custom event handlers
process data that gets rendered without sanitization.

SEVERITY: HIGH
Event handlers are common XSS vectors. Multiple event types can be exploited.
Custom event listeners with innerHTML are particularly dangerous.
""",
    "attack_vector": """
ONERROR HANDLER:
source.onerror = (e) => {
  errorDiv.innerHTML = `SSE Error: ${e.target.url}`;
};

CUSTOM EVENT LISTENER:
source.addEventListener('notification', (e) => {
  notify.innerHTML = e.data;
});

MULTIPLE HANDLERS:
['update', 'alert', 'news'].forEach(type => {
  source.addEventListener(type, e => {
    div.innerHTML += `<p>${e.data}</p>`;
  });
});

ONOPEN REFLECTION:
source.onopen = () => {
  status.innerHTML = `Connected to ${source.url}`;
};

DYNAMIC HANDLER:
source.addEventListener(eventType, (e) => {
  window[e.data]();  // Code execution
});

ERROR DETAIL:
source.onerror = (e) => {
  log.innerHTML = JSON.stringify(e);
};

RECONNECT HANDLER:
// After reconnect, old XSS data replayed
""",
    "remediation": """
DEFENSE:

1. SANITIZE event data before DOM insertion
2. Use textContent for display
3. Validate event types
4. Don't reflect errors in DOM
5. Use typed handlers
6. Implement CSP

SAFE HANDLERS:
source.onerror = () => {
  errorDiv.textContent = 'Connection error';
};

source.onopen = () => {
  status.textContent = 'Connected';
};

source.addEventListener('notification', (e) => {
  const p = document.createElement('p');
  p.textContent = e.data;
  notify.appendChild(p);
});

// With sanitization:
source.onmessage = (e) => {
  const clean = DOMPurify.sanitize(e.data);
  content.innerHTML = clean;
};

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
""",
}
