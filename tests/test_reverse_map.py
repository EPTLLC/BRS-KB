#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for reverse_map module
"""

from brs_kb.reverse_map import (
    ContextPattern,
    analyze_payload_with_patterns,
    find_contexts_for_payload,
    get_defense_info,
    get_defenses_for_context,
    get_reverse_map_info,
    predict_contexts_ml_ready,
)


class TestFindContextsForPayload:
    """Test find_contexts_for_payload function"""

    def test_script_payload(self):
        """Test script tag payload"""
        result = find_contexts_for_payload("<script>alert(1)</script>")

        assert isinstance(result, dict)
        assert "contexts" in result
        assert "confidence" in result
        assert "analysis_method" in result
        assert len(result["contexts"]) > 0
        assert result["confidence"] > 0

    def test_javascript_protocol_payload(self):
        """Test javascript: protocol payload"""
        result = find_contexts_for_payload("javascript:alert(1)")

        assert isinstance(result, dict)
        assert len(result["contexts"]) > 0
        assert "url" in result["contexts"] or result["confidence"] > 0

    def test_event_handler_payload(self):
        """Test event handler payload"""
        result = find_contexts_for_payload("<img onerror=alert(1)>")

        assert isinstance(result, dict)
        assert len(result["contexts"]) > 0

    def test_empty_payload(self):
        """Test empty payload"""
        result = find_contexts_for_payload("")

        assert isinstance(result, dict)
        assert result["contexts"] == []
        assert result["analysis_method"] == "none"

    def test_whitespace_payload(self):
        """Test whitespace-only payload"""
        result = find_contexts_for_payload("   ")

        assert isinstance(result, dict)
        assert result["contexts"] == []
        assert result["analysis_method"] == "none"

    def test_unknown_payload(self):
        """Test unknown payload"""
        result = find_contexts_for_payload("completely_unknown_payload_xyz123")

        assert isinstance(result, dict)
        # May or may not find contexts, but should return valid structure
        assert isinstance(result["contexts"], list)
        assert isinstance(result["confidence"], (int, float))

    def test_template_injection_payload(self):
        """Test template injection payload"""
        result = find_contexts_for_payload("{{constructor.constructor('alert(1)')()}}")

        assert isinstance(result, dict)
        assert len(result["contexts"]) > 0

    def test_svg_payload(self):
        """Test SVG payload"""
        result = find_contexts_for_payload("<svg onload=alert(1)>")

        assert isinstance(result, dict)
        assert len(result["contexts"]) > 0


class TestGetDefensesForContext:
    """Test get_defenses_for_context function"""

    def test_defenses_for_html_content(self):
        """Test defenses for html_content context"""
        defenses = get_defenses_for_context("html_content")

        assert isinstance(defenses, list)
        assert len(defenses) > 0

        for defense in defenses:
            assert "defense" in defense
            assert "priority" in defense
            assert "required" in defense

    def test_defenses_for_javascript_context(self):
        """Test defenses for javascript"""
        defenses = get_defenses_for_context("javascript")

        assert isinstance(defenses, list)
        assert len(defenses) > 0

    def test_defenses_for_unknown_context(self):
        """Test defenses for unknown context"""
        defenses = get_defenses_for_context("unknown_context_xyz")

        assert isinstance(defenses, list)
        # May return empty list or default defenses

    def test_defense_structure(self):
        """Test defense structure"""
        defenses = get_defenses_for_context("html_content")

        if len(defenses) > 0:
            defense = defenses[0]
            assert isinstance(defense["defense"], str)
            assert isinstance(defense["priority"], int)
            assert isinstance(defense["required"], bool)


class TestGetDefenseInfo:
    """Test get_defense_info function"""

    def test_defense_info_csp(self):
        """Test CSP defense info"""
        info = get_defense_info("csp")

        assert isinstance(info, dict)
        assert "effective_against" in info
        assert "implementation" in info

    def test_defense_info_html_encoding(self):
        """Test HTML encoding defense info"""
        info = get_defense_info("html_encoding")

        assert isinstance(info, dict)
        assert "effective_against" in info

    def test_defense_info_unknown(self):
        """Test unknown defense info"""
        info = get_defense_info("unknown_defense_xyz")

        assert isinstance(info, dict)
        # May return empty dict or default info


class TestGetReverseMapInfo:
    """Test get_reverse_map_info function"""

    def test_reverse_map_info(self):
        """Test reverse map info"""
        info = get_reverse_map_info()

        assert isinstance(info, dict)
        assert "version" in info
        assert "total_patterns" in info
        assert "supported_contexts" in info
        assert "ml_ready" in info

        assert info["version"] == "4.0.0"
        assert info["ml_ready"] is True
        assert len(info["supported_contexts"]) > 0


class TestPredictContextsMLReady:
    """Test predict_contexts_ml_ready function"""

    def test_ml_ready_features(self):
        """Test ML-ready feature extraction"""
        result = predict_contexts_ml_ready("<script>alert(1)</script>")

        assert isinstance(result, dict)
        assert "features" in result
        assert "ml_ready" in result
        assert result["ml_ready"] is True

        features = result["features"]
        assert "length" in features
        assert "has_script" in features
        assert isinstance(features["length"], int)
        assert isinstance(features["has_script"], bool)

    def test_ml_ready_empty_payload(self):
        """Test ML-ready features for empty payload"""
        result = predict_contexts_ml_ready("")

        assert isinstance(result, dict)
        assert "features" in result
        assert result["features"]["length"] == 0

    def test_ml_ready_features_structure(self):
        """Test ML-ready features structure"""
        result = predict_contexts_ml_ready("javascript:alert(1)")

        features = result["features"]
        assert "length" in features
        assert "special_chars" in features
        assert isinstance(features["length"], int)
        assert isinstance(features["special_chars"], int)


class TestAnalyzePayloadWithPatterns:
    """Test analyze_payload_with_patterns function"""

    def test_analyze_script_pattern(self):
        """Test analyzing script pattern"""
        matches = analyze_payload_with_patterns("<script>alert(1)</script>")

        assert isinstance(matches, list)
        assert len(matches) > 0

        for pattern, confidence in matches:
            assert isinstance(pattern, ContextPattern)
            assert isinstance(confidence, float)
            assert 0.0 <= confidence <= 1.0

    def test_analyze_empty_payload(self):
        """Test analyzing empty payload"""
        matches = analyze_payload_with_patterns("")

        assert isinstance(matches, list)

    def test_analyze_multiple_matches(self):
        """Test payload matching multiple patterns"""
        payload = "<img onerror=alert(1)>"
        matches = analyze_payload_with_patterns(payload)

        assert isinstance(matches, list)
        # May match multiple patterns

    def test_confidence_scores(self):
        """Test confidence scores"""
        matches = analyze_payload_with_patterns("<script>alert(1)</script>")

        if len(matches) > 0:
            # Scores should be sorted descending
            scores = [conf for _, conf in matches]
            assert scores == sorted(scores, reverse=True)


class TestContextPattern:
    """Test ContextPattern dataclass"""

    def test_context_pattern_creation(self):
        """Test creating ContextPattern"""
        pattern = ContextPattern(
            pattern=r"<script>",
            contexts=["html_content"],
            severity="critical",
            confidence=1.0,
            tags=["script"],
        )

        assert pattern.pattern == r"<script>"
        assert pattern.contexts == ["html_content"]
        assert pattern.severity == "critical"
        assert pattern.confidence == 1.0
        assert pattern.tags == ["script"]

    def test_context_pattern_defaults(self):
        """Test ContextPattern with defaults"""
        pattern = ContextPattern(
            pattern=r"test",
            contexts=["test"],
            severity="low",
        )

        assert pattern.confidence == 1.0
        assert pattern.tags == []
