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

from .patterns import ContextPattern, CONTEXT_PATTERNS
from .defenses import DEFENSE_TO_EFFECTIVENESS, CONTEXT_TO_DEFENSES
from .analysis import analyze_payload_with_patterns, find_contexts_for_payload
from .utils import (
    get_recommended_defenses,
    get_defense_effectiveness,
    get_reverse_map_info,
    get_defenses_for_context,
    get_defense_info,
    find_payload_bypasses,
    predict_contexts_ml_ready,
    reverse_lookup,
)

# Legacy compatibility
PAYLOAD_TO_CONTEXT = {
    "<script>alert(1)</script>": {
        "contexts": ["html_content", "html_comment", "svg_context"],
        "severity": "critical",
        "defenses": ["html_encoding", "csp", "sanitization"],
    },
    "<img src=x onerror=alert(1)>": {
        "contexts": ["html_content", "markdown_context", "xml_content"],
        "severity": "high",
        "defenses": ["html_encoding", "attribute_sanitization", "csp"],
    },
    "javascript:alert(1)": {
        "contexts": ["url_context", "html_attribute"],
        "severity": "high",
        "defenses": ["url_validation", "protocol_whitelist"],
    },
}

REVERSE_MAP_VERSION = "3.0.0"
TOTAL_PATTERNS = len(CONTEXT_PATTERNS)
SUPPORTED_CONTEXTS = set()
for pattern in CONTEXT_PATTERNS:
    SUPPORTED_CONTEXTS.update(pattern.contexts)
SUPPORTED_CONTEXTS.update([
    "html_content", "html_attribute", "html_comment", "javascript_context",
    "js_string", "js_object", "css_context", "svg_context", "markdown_context",
    "json_value", "xml_content", "url_context", "dom_xss", "template_injection",
    "postmessage_xss", "wasm_context", "default",
])

__all__ = [
    "ContextPattern",
    "CONTEXT_PATTERNS",
    "DEFENSE_TO_EFFECTIVENESS",
    "CONTEXT_TO_DEFENSES",
    "analyze_payload_with_patterns",
    "find_contexts_for_payload",
    "get_recommended_defenses",
    "get_defense_effectiveness",
    "get_reverse_map_info",
    "get_defenses_for_context",
    "get_defense_info",
    "find_payload_bypasses",
    "predict_contexts_ml_ready",
    "reverse_lookup",
    "PAYLOAD_TO_CONTEXT",
    "REVERSE_MAP_VERSION",
    "TOTAL_PATTERNS",
    "SUPPORTED_CONTEXTS",
]

