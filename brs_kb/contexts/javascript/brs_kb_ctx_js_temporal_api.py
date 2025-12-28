#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Knowledge Base: Temporal API XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via Temporal API",
    "severity": "medium",
    "cvss_score": 6.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "reliability": "medium",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "temporal", "date", "time", "modern", "proposal"],
    "description": """
Temporal API (proposal) provides modern date/time handling. XSS vulnerabilities occur when
user input controls Temporal object creation, formatting, or timezone without validation.

SEVERITY: MEDIUM
Modern API with limited adoption. Can lead to timezone confusion and data manipulation.
""",
    "attack_vector": """
TEMPORAL INSTANT INJECTION:
const instant = Temporal.Instant.from(userInput);  // XSS if input is malicious
const html = instant.toString();
document.body.innerHTML = html;  // XSS if toString() returns HTML

TEMPORAL PLAIN DATE INJECTION:
const date = Temporal.PlainDate.from(userInput);
element.innerHTML = date.toString();  // XSS

TEMPORAL ZONED DATETIME:
const zdt = Temporal.ZonedDateTime.from(userInput);
const text = zdt.toString({ timeZone: userInput });  // XSS if timeZone is controlled

TEMPORAL DURATION:
const duration = Temporal.Duration.from(userInput);
const html = duration.toString();
document.body.innerHTML = html;  // XSS

TEMPORAL CALENDAR:
const calendar = new Temporal.Calendar(userInput);  // XSS if calendar ID is controlled
const date = calendar.dateFromFields({ year: 2025, month: 1, day: 1 });
""",
    "remediation": """
DEFENSE:

1. Validate all Temporal input formats
2. Sanitize Temporal string outputs before rendering
3. Validate timezone identifiers
4. Use textContent instead of innerHTML
5. Implement input validation

SAFE PATTERN:
try {
  const instant = Temporal.Instant.from(userInput);
  element.textContent = instant.toString();  // Safe
} catch (e) {
  throw new Error('Invalid date format');
}

TIMEZONE VALIDATION:
const allowedTimezones = ['UTC', 'America/New_York', 'Europe/London'];
if (!allowedTimezones.includes(userInput)) {
  throw new Error('Invalid timezone');
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Temporal API Proposal
""",
}
