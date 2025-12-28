#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Reverse mapping package
Main entry point for reverse mapping functionality
"""

from .analysis import analyze_payload_with_patterns, find_contexts_for_payload
from .defenses import CONTEXT_TO_DEFENSES, DEFENSE_TO_EFFECTIVENESS
from .patterns import CONTEXT_PATTERNS, ContextPattern
from .utils import (
    find_payload_bypasses,
    get_defense_effectiveness,
    get_defense_info,
    get_defenses_for_context,
    get_recommended_defenses,
    get_reverse_map_info,
    predict_contexts_ml_ready,
    reverse_lookup,
)


# Legacy compatibility
PAYLOAD_TO_CONTEXT = {
    "<script>alert(1)</script>": {
        "contexts": ["html_content", "html_comment", "svg"],
        "severity": "critical",
        "defenses": ["html_encoding", "csp", "sanitization"],
    },
    "<img src=x onerror=alert(1)>": {
        "contexts": ["html_content", "markdown", "xml"],
        "severity": "high",
        "defenses": ["html_encoding", "attribute_sanitization", "csp"],
    },
    "javascript:alert(1)": {
        "contexts": ["url", "html_attribute"],
        "severity": "high",
        "defenses": ["url_validation", "protocol_whitelist"],
    },
}

# Version from single source
from brs_kb.version import REVERSE_MAP_VERSION


TOTAL_PATTERNS = len(CONTEXT_PATTERNS)
SUPPORTED_CONTEXTS = set()
for pattern in CONTEXT_PATTERNS:
    SUPPORTED_CONTEXTS.update(pattern.contexts)
SUPPORTED_CONTEXTS.update(
    [
        "html_content",
        "html_attribute",
        "html_comment",
        "javascript",
        "js_string",
        "js_object",
        "css",
        "svg",
        "markdown",
        "json_value",
        "xml",
        "url",
        "dom_xss",
        "template_injection",
        "postmessage",
        "wasm",
        "default",
    ]
)

__all__ = [
    "CONTEXT_PATTERNS",
    "CONTEXT_TO_DEFENSES",
    "DEFENSE_TO_EFFECTIVENESS",
    "PAYLOAD_TO_CONTEXT",
    "REVERSE_MAP_VERSION",
    "SUPPORTED_CONTEXTS",
    "TOTAL_PATTERNS",
    "ContextPattern",
    "analyze_payload_with_patterns",
    "find_contexts_for_payload",
    "find_payload_bypasses",
    "get_defense_effectiveness",
    "get_defense_info",
    "get_defenses_for_context",
    "get_recommended_defenses",
    "get_reverse_map_info",
    "predict_contexts_ml_ready",
    "reverse_lookup",
]
