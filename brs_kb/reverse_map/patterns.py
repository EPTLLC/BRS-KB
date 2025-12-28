#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Reverse mapping patterns
Context detection patterns for XSS payloads
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class ContextPattern:
    """Pattern for automatic context detection"""

    pattern: str
    contexts: List[str]
    severity: str
    confidence: float = 1.0
    tags: List[str] = field(default_factory=list)


# Automatic context detection patterns
CONTEXT_PATTERNS: List[ContextPattern] = [
    # HTML Content patterns
    ContextPattern(
        r"<script[^>]*>.*?</script>",
        ["html_content"],
        "critical",
        tags=["script_injection", "direct_execution"],
    ),
    ContextPattern(
        r"on\w+\s*=",
        ["html_content", "html_attribute"],
        "high",
        tags=["event_handler", "attribute_injection"],
    ),
    ContextPattern(
        r"<img[^>]*onerror[^>]*>",
        ["html_attribute"],
        "high",
        tags=["image_error", "event_injection"],
    ),
    ContextPattern(
        r"<svg[^>]*on\w+[^>]*>", ["svg"], "high", tags=["svg_injection", "event_handler"]
    ),
    ContextPattern(
        r'<iframe[^>]*src\s*=\s*["\']?\s*javascript:',
        ["html_attribute"],
        "high",
        tags=["iframe_injection", "protocol_injection"],
    ),
    ContextPattern(
        r"<body[^>]*on\w+[^>]*>", ["html_content"], "medium", tags=["body_event", "dom_injection"]
    ),
    # JavaScript Context patterns
    ContextPattern(
        r"^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[:=]\s*[^;]+;\s*alert\(",
        ["javascript"],
        "critical",
        tags=["variable_injection", "code_injection"],
    ),
    ContextPattern(
        r"javascript:", ["url"], "high", tags=["protocol_injection", "url_manipulation"]
    ),
    ContextPattern(r"vbscript:", ["url"], "medium", tags=["vbscript_injection", "legacy_protocol"]),
    ContextPattern(r"data:text/html,<script", ["url"], "high", tags=["data_uri", "html_injection"]),
    ContextPattern(
        r'[\'"`]?\s*\+\s*[^\'"`]*alert\(',
        ["js_string"],
        "critical",
        tags=["string_concatenation", "expression_injection"],
    ),
    # Template injection patterns
    ContextPattern(
        r"\{\{.*constructor\.constructor.*\}\}",
        ["template_injection"],
        "critical",
        tags=["template_sandbox_escape", "code_execution"],
    ),
    ContextPattern(
        r"#\{.*\}", ["template_injection"], "high", tags=["ruby_template", "erb_injection"]
    ),
    ContextPattern(
        r"<%.*%>", ["template_injection"], "high", tags=["asp_template", "server_injection"]
    ),
    ContextPattern(
        r"\$\{.*\}", ["template_injection"], "high", tags=["java_template", "el_injection"]
    ),
    # Modern web patterns
    ContextPattern(
        r"WebSocket\(.*\)", ["websocket"], "high", tags=["websocket_injection", "real_time"]
    ),
    ContextPattern(
        r"serviceWorker\.register\(.*\)",
        ["service_worker"],
        "high",
        tags=["service_worker", "background_script"],
    ),
    ContextPattern(
        r"RTCPeerConnection\(.*\)",
        ["webrtc"],
        "high",
        tags=["webrtc_injection", "media_injection"],
    ),
    ContextPattern(
        r"indexedDB\.open\(.*\)",
        ["indexeddb"],
        "medium",
        tags=["storage_injection", "database_xss"],
    ),
    ContextPattern(r"WebGL.*shader", ["webgl"], "medium", tags=["shader_injection", "gpu_xss"]),
    # Protocol and encoding patterns
    ContextPattern(
        r"&#\d+;", ["html_content"], "medium", 0.7, tags=["html_entity", "encoding_bypass"]
    ),
    ContextPattern(
        r"%[0-9a-fA-F][0-9a-fA-F]",
        ["url"],
        "medium",
        0.8,
        tags=["url_encoding", "protocol_injection"],
    ),
    ContextPattern(
        r"\\x[0-9a-fA-F][0-9a-fA-F]",
        ["javascript"],
        "medium",
        0.8,
        tags=["hex_encoding", "js_injection"],
    ),
    ContextPattern(
        r"\\u[0-9a-fA-F]{4}",
        ["javascript"],
        "medium",
        0.7,
        tags=["unicode_encoding", "js_injection"],
    ),
    # CSS Context patterns
    ContextPattern(
        r"<style>.*expression\(.*\)</style>",
        ["css"],
        "high",
        tags=["css_expression", "legacy_ie"],
    ),
    ContextPattern(
        r"background\s*:\s*url\(.*javascript:",
        ["css"],
        "high",
        tags=["css_url", "background_injection"],
    ),
    ContextPattern(
        r"@import.*javascript:", ["css"], "high", tags=["css_import", "external_injection"]
    ),
    # Comment-based patterns
    ContextPattern(
        r"<!--.*?-->.*?alert\(",
        ["html_comment"],
        "medium",
        0.6,
        tags=["comment_injection", "hidden_injection"],
    ),
    ContextPattern(
        r"/\*.*\*/.*?alert\(", ["css"], "low", 0.4, tags=["css_comment", "hidden_injection"]
    ),
]
