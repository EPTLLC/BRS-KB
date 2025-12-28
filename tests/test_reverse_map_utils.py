#!/usr/bin/env python3

"""
Tests for reverse_map/utils.py
"""

from brs_kb.reverse_map.utils import (
    find_payload_bypasses,
    get_defense_effectiveness,
    get_recommended_defenses,
    get_reverse_map_info,
    predict_contexts_ml_ready,
    reverse_lookup,
)


class TestGetRecommendedDefenses:
    """Test get_recommended_defenses function"""

    def test_get_recommended_defenses_existing(self):
        """Test getting defenses for existing context"""
        result = get_recommended_defenses("html_content")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_get_recommended_defenses_nonexistent(self):
        """Test getting defenses for non-existent context"""
        result = get_recommended_defenses("nonexistent_context_12345")
        assert isinstance(result, list)
        assert len(result) == 0


class TestGetDefenseEffectiveness:
    """Test get_defense_effectiveness function"""

    def test_get_defense_effectiveness_existing(self):
        """Test getting effectiveness for existing defense"""
        result = get_defense_effectiveness("html_encoding")
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_get_defense_effectiveness_nonexistent(self):
        """Test getting effectiveness for non-existent defense"""
        result = get_defense_effectiveness("nonexistent_defense_12345")
        assert isinstance(result, dict)
        assert len(result) == 0


class TestFindPayloadBypasses:
    """Test find_payload_bypasses function"""

    def test_find_payload_bypasses(self):
        """Test finding bypasses for a payload"""
        payload = "<script>alert(1)</script>"
        result = find_payload_bypasses(payload)
        assert isinstance(result, list)


class TestPredictContextsMlReady:
    """Test predict_contexts_ml_ready function"""

    def test_predict_contexts_ml_ready(self):
        """Test ML-ready prediction"""
        payload = "<script>alert(1)</script>"
        result = predict_contexts_ml_ready(payload)

        assert isinstance(result, dict)
        assert "features" in result
        assert "ml_ready" in result
        assert result["ml_ready"] is True
        assert isinstance(result["features"], dict)
        assert "length" in result["features"]


class TestReverseLookup:
    """Test reverse_lookup function"""

    def test_reverse_lookup_payload(self):
        """Test reverse lookup with payload type"""
        result = reverse_lookup("payload", "<script>alert(1)</script>")
        assert isinstance(result, dict)
        assert "contexts" in result

    def test_reverse_lookup_context(self):
        """Test reverse lookup with context type"""
        result = reverse_lookup("context", "html_content")
        assert isinstance(result, dict)
        assert "defenses" in result

    def test_reverse_lookup_defense(self):
        """Test reverse lookup with defense type"""
        result = reverse_lookup("defense", "html_encoding")
        assert isinstance(result, dict)

    def test_reverse_lookup_pattern(self):
        """Test reverse lookup with pattern type"""
        result = reverse_lookup("pattern", "script")
        assert isinstance(result, dict)
        assert "patterns" in result
        assert "count" in result

    def test_reverse_lookup_invalid(self):
        """Test reverse lookup with invalid type"""
        result = reverse_lookup("invalid_type", "test")
        assert isinstance(result, dict)
        assert len(result) == 0


class TestGetReverseMapInfo:
    """Test get_reverse_map_info function"""

    def test_get_reverse_map_info(self):
        """Test getting reverse map info"""
        result = get_reverse_map_info()
        assert isinstance(result, dict)
        assert "patterns_count" in result
        assert "defenses_count" in result
        assert "contexts_covered" in result
