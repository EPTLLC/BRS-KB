#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Reverse mapping analysis functions
Core analysis functions for payload context detection
"""

import re
import time
from functools import lru_cache
from typing import Dict, List, Tuple

from .defenses import CONTEXT_TO_DEFENSES
from .patterns import CONTEXT_PATTERNS, ContextPattern


# Pre-compile regex patterns for better performance
_COMPILED_PATTERNS = [
    (pattern, re.compile(pattern.pattern, re.IGNORECASE | re.MULTILINE))
    for pattern in CONTEXT_PATTERNS
]


@lru_cache(maxsize=256)
def analyze_payload_with_patterns(payload: str) -> List[Tuple[ContextPattern, float]]:
    """
    Analyze payload against all patterns and return matches with confidence scores.
    Returns list of (pattern, confidence) tuples sorted by confidence.
    Uses cached compiled regex patterns for performance.
    """
    matches = []

    for pattern, compiled_regex in _COMPILED_PATTERNS:
        # Use pre-compiled regex
        match = compiled_regex.search(payload)

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


@lru_cache(maxsize=512)
def find_contexts_for_payload(payload: str) -> Dict:
    """
    Enhanced payload analysis with automatic context detection and payload database integration.
    Uses pattern matching, payload database lookup, and confidence scoring for maximum accuracy.
    Results are cached for frequently analyzed payloads.
    """
    from brs_kb.metrics import record_payload_analysis

    start_time = time.time()

    if not payload or not payload.strip():
        return {
            "contexts": [],
            "confidence": 0.0,
            "patterns_matched": [],
            "recommended_defenses": [],
            "severity": "none",
            "ml_features": {},
            "analysis_method": "none",
        }

    # Step 1: Pattern matching
    pattern_matches = analyze_payload_with_patterns(payload)

    # Step 2: Extract contexts from patterns
    detected_contexts = set()
    for pattern, _confidence in pattern_matches:
        detected_contexts.update(pattern.contexts)

    # Step 3: Lookup in payload database
    try:
        from brs_kb.payloads import search_payloads

        db_results = search_payloads(payload[:50])  # Search with first 50 chars
        db_contexts = set()
        for db_payload, _relevance in db_results[:5]:  # Top 5 results
            db_contexts.update(db_payload.contexts)
        detected_contexts.update(db_contexts)
    except Exception:
        pass  # Database lookup failed, continue with patterns only

    # Step 4: Calculate overall confidence
    if pattern_matches:
        max_confidence = max(conf for _, conf in pattern_matches)
        avg_confidence = sum(conf for _, conf in pattern_matches) / len(pattern_matches)
        overall_confidence = max_confidence * 0.7 + avg_confidence * 0.3
    else:
        overall_confidence = 0.3 if detected_contexts else 0.0

    # Step 5: Determine severity
    if pattern_matches:
        severities = [p.severity for p, _ in pattern_matches]
        if "critical" in severities:
            severity = "critical"
        elif "high" in severities:
            severity = "high"
        else:
            severity = severities[0] if severities else "medium"
    else:
        severity = "low"

    # Step 6: Get recommended defenses
    recommended_defenses = []
    for context in detected_contexts:
        if context in CONTEXT_TO_DEFENSES:
            recommended_defenses.extend(CONTEXT_TO_DEFENSES[context])

    # Remove duplicates while preserving order
    seen = set()
    unique_defenses = []
    for defense in recommended_defenses:
        defense_key = defense["defense"]
        if defense_key not in seen:
            seen.add(defense_key)
            unique_defenses.append(defense)

    # Step 7: ML-ready features
    ml_features = {
        "payload_length": len(payload),
        "pattern_matches_count": len(pattern_matches),
        "contexts_count": len(detected_contexts),
        "max_confidence": max_confidence if pattern_matches else 0.0,
        "avg_confidence": avg_confidence if pattern_matches else 0.0,
        "has_script_tag": "<script" in payload.lower(),
        "has_event_handler": bool(re.search(r"on\w+\s*=", payload, re.IGNORECASE)),
        "has_javascript_protocol": "javascript:" in payload.lower(),
        "has_encoding": bool(re.search(r"[%&#\\]", payload)),
    }

    duration = time.time() - start_time
    record_payload_analysis(payload, duration, len(detected_contexts), overall_confidence)

    return {
        "contexts": sorted(detected_contexts),
        "confidence": round(overall_confidence, 3),
        "patterns_matched": [
            {
                "pattern": p.pattern,
                "contexts": p.contexts,
                "severity": p.severity,
                "confidence": round(c, 3),
                "tags": p.tags,
            }
            for p, c in pattern_matches[:5]  # Top 5 patterns
        ],
        "recommended_defenses": unique_defenses[:10],  # Top 10 defenses
        "severity": severity,
        "ml_features": ml_features,
        "analysis_method": "pattern_matching",
    }
