#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Enhanced
Telegram: https://t.me/easyprotech

Advanced Reverse Mapping System: Payload → Context → Defense
Enhanced with automatic context detection and ML-ready architecture
"""

import re
from typing import List, Dict, Set, Tuple, Optional, Any
from dataclasses import dataclass, field


# Enhanced payload patterns for automatic context detection
@dataclass
class ContextPattern:
    """Pattern for automatic context detection"""

    pattern: str
    contexts: List[str]
    severity: str
    confidence: float = 1.0
    tags: List[str] = field(default_factory=list)


# Automatic context detection patterns
CONTEXT_PATTERNS = [
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
        r"<svg[^>]*on\w+[^>]*>", ["svg_context"], "high", tags=["svg_injection", "event_handler"]
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
        ["javascript_context"],
        "critical",
        tags=["variable_injection", "code_injection"],
    ),
    ContextPattern(
        r"javascript:", ["url_context"], "high", tags=["protocol_injection", "url_manipulation"]
    ),
    ContextPattern(
        r"vbscript:", ["url_context"], "medium", tags=["vbscript_injection", "legacy_protocol"]
    ),
    ContextPattern(
        r"data:text/html,<script", ["url_context"], "high", tags=["data_uri", "html_injection"]
    ),
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
        r"WebSocket\(.*\)", ["websocket_xss"], "high", tags=["websocket_injection", "real_time"]
    ),
    ContextPattern(
        r"serviceWorker\.register\(.*\)",
        ["service_worker_xss"],
        "high",
        tags=["service_worker", "background_script"],
    ),
    ContextPattern(
        r"RTCPeerConnection\(.*\)",
        ["webrtc_xss"],
        "high",
        tags=["webrtc_injection", "media_injection"],
    ),
    ContextPattern(
        r"indexedDB\.open\(.*\)",
        ["indexeddb_xss"],
        "medium",
        tags=["storage_injection", "database_xss"],
    ),
    ContextPattern(r"WebGL.*shader", ["webgl_xss"], "medium", tags=["shader_injection", "gpu_xss"]),
    # Protocol and encoding patterns
    ContextPattern(
        r"&#\d+;", ["html_content"], "medium", 0.7, tags=["html_entity", "encoding_bypass"]
    ),
    ContextPattern(
        r"%[0-9a-fA-F][0-9a-fA-F]",
        ["url_context"],
        "medium",
        0.8,
        tags=["url_encoding", "protocol_injection"],
    ),
    ContextPattern(
        r"\\x[0-9a-fA-F][0-9a-fA-F]",
        ["javascript_context"],
        "medium",
        0.8,
        tags=["hex_encoding", "js_injection"],
    ),
    ContextPattern(
        r"\\u[0-9a-fA-F]{4}",
        ["javascript_context"],
        "medium",
        0.7,
        tags=["unicode_encoding", "js_injection"],
    ),
    # CSS Context patterns
    ContextPattern(
        r"<style>.*expression\(.*\)</style>",
        ["css_context"],
        "high",
        tags=["css_expression", "legacy_ie"],
    ),
    ContextPattern(
        r"background\s*:\s*url\(.*javascript:",
        ["css_context"],
        "high",
        tags=["css_url", "background_injection"],
    ),
    ContextPattern(
        r"@import.*javascript:", ["css_context"], "high", tags=["css_import", "external_injection"]
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
        r"/\*.*\*/.*?alert\(", ["css_context"], "low", 0.4, tags=["css_comment", "hidden_injection"]
    ),
]

# Enhanced Defense → Effectiveness mapping with modern techniques
DEFENSE_TO_EFFECTIVENESS = {
    "html_encoding": {
        "effective_against": ["html_content", "html_attribute", "html_comment"],
        "implementation": [
            "htmlspecialchars($input, ENT_QUOTES, 'UTF-8')",  # PHP
            "html.escape(input, quote=True)",  # Python
            "element.textContent = input",  # JavaScript
        ],
        "bypass_difficulty": "high",
        "tags": ["encoding", "output_sanitization"],
    },
    "csp": {
        "effective_against": [
            "html_content",
            "javascript_context",
            "css_context",
            "svg_context",
            "template_injection",
            "websocket_xss",
        ],
        "implementation": [
            "Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}'; object-src 'none'"
        ],
        "bypass_difficulty": "very_high",
        "tags": ["policy", "browser_enforcement"],
    },
    "javascript_encoding": {
        "effective_against": ["js_string", "javascript_context"],
        "implementation": [
            "JSON.stringify(input)",
            "json.dumps(input)",
            "json_encode($input, JSON_HEX_TAG)",
        ],
        "bypass_difficulty": "high",
        "tags": ["serialization", "json_security"],
    },
    "url_validation": {
        "effective_against": ["url_context", "html_attribute"],
        "implementation": [
            "new URL(input, base)",  # JavaScript
            "urllib.parse.urlparse(input)",  # Python
            "parse_url($input)",  # PHP
        ],
        "bypass_difficulty": "medium",
        "tags": ["url_parsing", "protocol_validation"],
    },
    "sanitization": {
        "effective_against": ["html_content", "svg_context", "markdown_context", "xml_content"],
        "implementation": [
            "DOMPurify.sanitize(input)",  # JavaScript
            "bleach.clean(input)",  # Python
            "HTMLPurifier",  # PHP
        ],
        "bypass_difficulty": "medium",
        "tags": ["html_sanitization", "dom_cleaning"],
    },
    # New modern defenses
    "trusted_types": {
        "effective_against": ["html_content", "javascript_context", "dom_xss"],
        "implementation": [
            "trustedTypes.createPolicy('default', { createHTML: (s) => DOMPurify.sanitize(s) })"
        ],
        "bypass_difficulty": "very_high",
        "tags": ["browser_api", "modern_security"],
    },
    "csp_nonce": {
        "effective_against": ["html_content", "javascript_context"],
        "implementation": [
            "<script nonce='{random}'>...</script>",
            "Content-Security-Policy: script-src 'nonce-{random}'",
        ],
        "bypass_difficulty": "very_high",
        "tags": ["csp_enhancement", "inline_script_control"],
    },
    "waf_rules": {
        "effective_against": "all",
        "implementation": [
            "ModSecurity rules for XSS detection",
            "AWS WAF XSS protection",
            "Cloudflare XSS detection",
        ],
        "bypass_difficulty": "high",
        "tags": ["waf", "perimeter_security"],
    },
}

# Enhanced Context → Recommended defenses with modern contexts
CONTEXT_TO_DEFENSES = {
    "html_content": [
        {"defense": "html_encoding", "priority": 1, "required": True, "tags": ["primary"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
        {"defense": "sanitization", "priority": 2, "required": False, "tags": ["fallback"]},
    ],
    "html_attribute": [
        {"defense": "html_encoding", "priority": 1, "required": True, "tags": ["encoding"]},
        {"defense": "url_validation", "priority": 1, "required": True, "tags": ["validation"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    "javascript_context": [
        {"defense": "csp_nonce", "priority": 1, "required": True, "tags": ["modern", "inline"]},
        {"defense": "javascript_encoding", "priority": 1, "required": True, "tags": ["encoding"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
    ],
    "js_string": [
        {"defense": "javascript_encoding", "priority": 1, "required": True, "tags": ["primary"]},
        {"defense": "json_serialization", "priority": 1, "required": True, "tags": ["json"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    "url_context": [
        {"defense": "url_validation", "priority": 1, "required": True, "tags": ["primary"]},
        {"defense": "protocol_whitelist", "priority": 1, "required": True, "tags": ["whitelist"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    # New modern contexts
    "websocket_xss": [
        {"defense": "input_validation", "priority": 1, "required": True, "tags": ["websocket"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
        {"defense": "message_filtering", "priority": 1, "required": True, "tags": ["real-time"]},
    ],
    "service_worker_xss": [
        {"defense": "service_worker_validation", "priority": 1, "required": True, "tags": ["sw"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
        {
            "defense": "registration_control",
            "priority": 1,
            "required": True,
            "tags": ["registration"],
        },
    ],
    "webrtc_xss": [
        {"defense": "webrtc_validation", "priority": 1, "required": True, "tags": ["webrtc"]},
        {"defense": "media_control", "priority": 1, "required": True, "tags": ["media"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    "indexeddb_xss": [
        {"defense": "storage_validation", "priority": 1, "required": True, "tags": ["storage"]},
        {"defense": "data_sanitization", "priority": 1, "required": True, "tags": ["sanitization"]},
        {"defense": "access_control", "priority": 2, "required": False, "tags": ["permissions"]},
    ],
    "webgl_xss": [
        {"defense": "shader_validation", "priority": 1, "required": True, "tags": ["shader"]},
        {"defense": "webgl_sandbox", "priority": 1, "required": True, "tags": ["sandbox"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
    "template_injection": [
        {"defense": "template_sandboxing", "priority": 1, "required": True, "tags": ["sandbox"]},
        {"defense": "aot_compilation", "priority": 1, "required": True, "tags": ["compilation"]},
        {"defense": "csp", "priority": 1, "required": True, "tags": ["policy"]},
    ],
    "dom_xss": [
        {
            "defense": "trusted_types",
            "priority": 1,
            "required": True,
            "tags": ["modern", "browser"],
        },
        {"defense": "dom_sanitization", "priority": 1, "required": True, "tags": ["dom"]},
        {"defense": "csp", "priority": 2, "required": True, "tags": ["policy"]},
    ],
}


def analyze_payload_with_patterns(payload: str) -> List[Tuple[ContextPattern, float]]:
    """
    Analyze payload against all patterns and return matches with confidence scores.
    Returns list of (pattern, confidence) tuples sorted by confidence.
    """
    matches = []

    for pattern in CONTEXT_PATTERNS:
        # Check for regex match
        regex = re.compile(pattern.pattern, re.IGNORECASE | re.MULTILINE)
        match = regex.search(payload)

        if match:
            # Calculate confidence based on pattern specificity and match quality
            confidence = pattern.confidence

            # Boost confidence for exact matches vs partial
            if match.group() == payload.strip():
                confidence *= 1.2
            elif len(match.group()) > len(payload) * 0.7:
                confidence *= 1.1

            # Penalize low-confidence patterns
            if confidence < 0.5:
                confidence *= 0.8

            matches.append((pattern, min(confidence, 1.0)))

    # Sort by confidence (highest first)
    matches.sort(key=lambda x: x[1], reverse=True)
    return matches


def find_contexts_for_payload(payload: str) -> Dict:
    """
    Enhanced payload analysis with automatic context detection and payload database integration.
    Uses pattern matching, payload database lookup, and confidence scoring for maximum accuracy.
    """
    if not payload or not payload.strip():
        return {
            "contexts": [],
            "severity": "unknown",
            "defenses": [],
            "confidence": 0.0,
            "analysis_method": "none",
        }

    # First, check payload database for exact or similar matches
    from brs_kb.payloads_db import search_payloads

    search_results = search_payloads(payload)
    if search_results:
        # Found similar payload in database
        best_match = search_results[0]
        payload_entry, relevance = best_match

        return {
            "contexts": payload_entry.contexts,
            "severity": payload_entry.severity,
            "defenses": [d["defense"] for d in get_defenses_for_context(payload_entry.contexts[0])],
            "confidence": relevance,
            "analysis_method": "payload_database",
            "matched_patterns": 1,
            "matched_payload_id": payload_entry.payload[:50] + "...",
            "pattern_details": [
                {
                    "pattern": payload_entry.payload,
                    "contexts": payload_entry.contexts,
                    "confidence": relevance,
                    "tags": payload_entry.tags,
                }
            ],
            "tags": payload_entry.tags,
            "waf_evasion": payload_entry.waf_evasion,
            "browser_support": payload_entry.browser_support,
        }

    # Fallback to pattern matching
    pattern_matches = analyze_payload_with_patterns(payload)

    if not pattern_matches:
        # Final fallback to legacy exact matching
        legacy_result = PAYLOAD_TO_CONTEXT.get(payload.strip(), None)
        if legacy_result:
            return {**legacy_result, "confidence": 0.9, "analysis_method": "legacy_exact"}
        else:
            return {
                "contexts": ["default"],
                "severity": "medium",
                "defenses": ["input_validation", "sanitization"],
                "confidence": 0.3,
                "analysis_method": "fallback",
            }

    # Extract best matches from patterns
    best_patterns = pattern_matches[:3]  # Top 3 matches
    all_contexts = set()
    max_severity = "low"
    all_defenses = set()
    total_confidence = 0.0

    for pattern, confidence in best_patterns:
        all_contexts.update(pattern.contexts)
        max_severity = max(max_severity, pattern.severity)
        total_confidence += confidence

        # Add context-specific defenses
        for context in pattern.contexts:
            defenses = get_defenses_for_context(context)
            for defense in defenses:
                all_defenses.add(defense["defense"])

    avg_confidence = total_confidence / len(best_patterns)

    return {
        "contexts": sorted(list(all_contexts)),
        "severity": max_severity,
        "defenses": sorted(list(all_defenses)),
        "confidence": round(avg_confidence, 3),
        "analysis_method": "pattern_matching",
        "matched_patterns": len(pattern_matches),
        "pattern_details": [
            {"pattern": p.pattern, "contexts": p.contexts, "confidence": conf, "tags": p.tags}
            for p, conf in best_patterns
        ],
    }


def get_defenses_for_context(context: str) -> List[Dict[str, Any]]:
    """Get recommended defenses for a context with enhanced information"""
    defenses = CONTEXT_TO_DEFENSES.get(context, [])

    # Enhance defense info with effectiveness data
    enhanced_defenses: List[Dict[str, Any]] = []
    for defense in defenses:
        if isinstance(defense, dict) and "defense" in defense:
            defense_name = defense["defense"]
            if isinstance(defense_name, str):
                defense_info = DEFENSE_TO_EFFECTIVENESS.get(defense_name, {})
                enhanced_defenses.append(
                    {
                        **defense,
                        "bypass_difficulty": defense_info.get("bypass_difficulty", "unknown"),
                        "implementation": defense_info.get("implementation", []),
                        "tags": defense_info.get("tags", []),
                    }
                )

    return enhanced_defenses


def get_defense_info(defense: str) -> Dict:
    """Get detailed information about a defense mechanism"""
    return DEFENSE_TO_EFFECTIVENESS.get(defense, {})


def find_payload_bypasses(payload: str) -> List[str]:
    """Find contexts where payload might be blocked and suggest bypasses"""
    info = find_contexts_for_payload(payload)
    defenses = info.get("defenses", [])

    # Add general bypass techniques for common defenses
    bypasses = {
        "html_encoding": ["double_encoding", "nested_encoding", "unicode_normalization"],
        "csp": ["nonce_reuse", "hash_collision", "unsafe_eval"],
        "sanitization": ["dom_clobbering", "mutation_xss", "parser_differential"],
        "url_validation": ["protocol_relative", "encoding_bypass", "null_byte"],
        "waf_rules": ["fragmented_payload", "case_variation", "comment_obfuscation"],
    }

    suggested_bypasses = []
    for defense in defenses:
        if defense in bypasses:
            suggested_bypasses.extend(bypasses[defense])

    return suggested_bypasses


def predict_contexts_ml_ready(payload: str) -> Dict:
    """
    ML-ready payload analysis with feature extraction.
    Returns structured data for future ML integration.
    """
    features = {
        "length": len(payload),
        "has_script": "<script" in payload.lower(),
        "has_javascript": "javascript:" in payload.lower(),
        "has_onerror": "onerror=" in payload.lower(),
        "has_svg": "<svg" in payload.lower(),
        "has_template": any(t in payload for t in ["{{", "}}", "${", "<%", "%>"]),
        "has_encoding": any(e in payload for e in ["%20", "%22", "%27", "&#"]),
        "has_comments": any(c in payload for c in ["<!--", "/*", "//"]),
        "context_switches": payload.count('"') + payload.count("'") + payload.count("`"),
        "special_chars": sum(1 for c in payload if c in "<>\"'&"),
        "uppercase_ratio": sum(1 for c in payload if c.isupper()) / len(payload) if payload else 0,
    }

    analysis = find_contexts_for_payload(payload)

    return {**analysis, "features": features, "ml_ready": True, "timestamp": "2025-10-25T12:00:00Z"}


def reverse_lookup(query_type: str, query: str) -> Dict:
    """
    Universal reverse lookup function with enhanced capabilities

    query_type: 'payload', 'context', 'defense', 'pattern'
    query: the actual query string
    """
    if query_type == "payload":
        return find_contexts_for_payload(query)
    elif query_type == "context":
        return {
            "defenses": get_defenses_for_context(query),
            "context": query,
            "defense_count": len(get_defenses_for_context(query)),
        }
    elif query_type == "defense":
        return get_defense_info(query)
    elif query_type == "pattern":
        # Find patterns matching the query
        matching_patterns = [
            p
            for p in CONTEXT_PATTERNS
            if query.lower() in p.pattern.lower() or query.lower() in " ".join(p.tags).lower()
        ]
        return {
            "patterns": [
                {
                    "pattern": p.pattern,
                    "contexts": p.contexts,
                    "severity": p.severity,
                    "confidence": p.confidence,
                    "tags": p.tags,
                }
                for p in matching_patterns
            ],
            "count": len(matching_patterns),
        }
    else:
        return {}


# Legacy compatibility - keep old exact matches for backward compatibility
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
    "{{constructor.constructor('alert(1)')()}}": {
        "contexts": ["template_injection"],
        "severity": "critical",
        "defenses": ["template_sandboxing", "aot_compilation", "csp"],
    },
    "'; alert(1); var x='": {
        "contexts": ["js_string"],
        "severity": "critical",
        "defenses": ["javascript_encoding", "json_serialization", "csp"],
    },
    "<svg onload=alert(1)>": {
        "contexts": ["svg_context", "html_content"],
        "severity": "high",
        "defenses": ["svg_sanitization", "csp", "content_type_headers"],
    },
}

# Statistics and metadata
REVERSE_MAP_VERSION = "2.0.0"
TOTAL_PATTERNS = len(CONTEXT_PATTERNS)
SUPPORTED_CONTEXTS = set()
for pattern in CONTEXT_PATTERNS:
    SUPPORTED_CONTEXTS.update(pattern.contexts)

# Add legacy contexts to supported set
SUPPORTED_CONTEXTS.update(
    [
        "html_content",
        "html_attribute",
        "html_comment",
        "javascript_context",
        "js_string",
        "js_object",
        "css_context",
        "svg_context",
        "markdown_context",
        "json_value",
        "xml_content",
        "url_context",
        "dom_xss",
        "template_injection",
        "postmessage_xss",
        "wasm_context",
        "default",
    ]
)


def get_reverse_map_info() -> Dict:
    """Get reverse mapping system information"""
    return {
        "version": REVERSE_MAP_VERSION,
        "total_patterns": TOTAL_PATTERNS,
        "supported_contexts": sorted(list(SUPPORTED_CONTEXTS)),
        "analysis_methods": ["pattern_matching", "legacy_exact", "fallback"],
        "ml_ready": True,
        "confidence_scoring": True,
        "bypass_analysis": True,
    }


# Export all functions and variables
__all__ = [
    # Core functions
    "find_contexts_for_payload",
    "get_defenses_for_context",
    "get_defense_info",
    "find_payload_bypasses",
    "reverse_lookup",
    "predict_contexts_ml_ready",
    "analyze_payload_with_patterns",
    # Information functions
    "get_reverse_map_info",
    # Data structures (for backward compatibility)
    "PAYLOAD_TO_CONTEXT",
    "DEFENSE_TO_EFFECTIVENESS",
    "CONTEXT_TO_DEFENSES",
    "CONTEXT_PATTERNS",
    # Classes
    "ContextPattern",
    # Constants
    "REVERSE_MAP_VERSION",
    "TOTAL_PATTERNS",
    "SUPPORTED_CONTEXTS",
]
