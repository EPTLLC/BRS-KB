#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Reverse mapping utility functions
Helper functions for reverse mapping operations
"""

from functools import lru_cache
from typing import Any, Dict, List

from brs_kb.version import REVERSE_MAP_VERSION

from .analysis import find_contexts_for_payload
from .defenses import CONTEXT_TO_DEFENSES, DEFENSE_TO_EFFECTIVENESS
from .patterns import CONTEXT_PATTERNS


@lru_cache(maxsize=128)
def get_defenses_for_context(context: str) -> List[Dict[str, Any]]:
    """Get recommended defenses for a context with enhanced information (cached)"""
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


@lru_cache(maxsize=64)
def get_defense_info(defense: str) -> Dict:
    """Get detailed information about a defense mechanism (cached)"""
    return DEFENSE_TO_EFFECTIVENESS.get(defense, {})


def get_recommended_defenses(context: str) -> List[Dict[str, Any]]:
    """Get recommended defense strategies for a specific context"""
    return CONTEXT_TO_DEFENSES.get(context, [])


def get_defense_effectiveness(defense_name: str) -> Dict[str, Any]:
    """Get effectiveness information for a specific defense"""
    return DEFENSE_TO_EFFECTIVENESS.get(defense_name, {})


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


def get_reverse_map_info() -> Dict[str, Any]:
    """Get information about the reverse mapping system"""
    # Legacy compatibility - keep old exact matches

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

    return {
        "version": REVERSE_MAP_VERSION,
        "patterns_count": len(CONTEXT_PATTERNS),
        "total_patterns": len(CONTEXT_PATTERNS),
        "defenses_count": len(DEFENSE_TO_EFFECTIVENESS),
        "contexts_covered": len(CONTEXT_TO_DEFENSES),
        "supported_contexts": sorted(SUPPORTED_CONTEXTS),
        "available_defenses": list(DEFENSE_TO_EFFECTIVENESS.keys()),
        "analysis_methods": ["pattern_matching", "legacy_exact", "fallback"],
        "ml_ready": True,
        "confidence_scoring": True,
        "bypass_analysis": True,
    }
