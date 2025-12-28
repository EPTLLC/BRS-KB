#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Enhanced
Telegram: https://t.me/easyprotech

Enhanced Tests for BRS-KB - including reverse mapping functionality
"""

import pytest

from brs_kb import (
    __version__,
    get_all_contexts,
    get_kb_info,
    get_kb_version,
    get_vulnerability_details,
    list_contexts,
)
from brs_kb.reverse_map import (
    find_contexts_for_payload,
    get_reverse_map_info,
    predict_contexts_ml_ready,
)


class TestBasicFunctionality:
    """Test basic BRS-KB functionality."""

    def test_version_available(self):
        """Test that version is available."""
        assert __version__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0

    def test_get_kb_version(self):
        """Test getting KB version."""
        version = get_kb_version()
        assert version is not None
        assert isinstance(version, str)
        assert version == __version__

    def test_get_kb_info(self):
        """Test getting KB information."""
        info = get_kb_info()

        assert isinstance(info, dict)
        assert "version" in info
        assert "build" in info
        assert "revision" in info
        assert "total_contexts" in info
        assert "available_contexts" in info

        assert info["total_contexts"] > 0
        assert isinstance(info["available_contexts"], list)

    def test_list_contexts(self):
        """Test listing all contexts."""
        contexts = list_contexts()

        assert isinstance(contexts, list)
        assert len(contexts) > 0
        assert "html_content" in contexts
        assert "default" in contexts

    def test_get_all_contexts(self):
        """Test getting all contexts with details."""
        all_contexts = get_all_contexts()

        assert isinstance(all_contexts, dict)
        assert len(all_contexts) > 0

        # Check that each context has details
        for _context_name, details in all_contexts.items():
            assert isinstance(details, dict)
            assert "title" in details


class TestVulnerabilityDetails:
    """Test vulnerability details retrieval."""

    def test_get_known_context(self):
        """Test getting details for known context."""
        details = get_vulnerability_details("html_content")

        assert isinstance(details, dict)
        assert "title" in details
        assert "description" in details
        assert "attack_vector" in details
        assert "remediation" in details

    def test_get_unknown_context(self):
        """Test getting details for unknown context (should return default)."""
        details = get_vulnerability_details("totally_unknown_context_xyz")

        assert isinstance(details, dict)
        assert len(details) > 0  # Should return default, not empty

    def test_context_metadata(self):
        """Test that contexts have proper metadata."""
        details = get_vulnerability_details("html_content")

        # Check for metadata fields (if present)
        if "severity" in details:
            assert details["severity"] in ["low", "medium", "high", "critical"]

        if "cvss_score" in details:
            assert 0.0 <= details["cvss_score"] <= 10.0

        if "cwe" in details:
            assert isinstance(details["cwe"], list)

        if "tags" in details:
            assert isinstance(details["tags"], list)

    def test_required_fields(self):
        """Test that required fields are present."""
        details = get_vulnerability_details("html_content")

        # Required fields
        assert "title" in details
        assert "description" in details
        assert "attack_vector" in details
        assert "remediation" in details

        # Check that they're not empty
        assert len(details["title"]) > 0
        assert len(details["description"]) > 0
        assert len(details["attack_vector"]) > 0
        assert len(details["remediation"]) > 0


class TestContextCoverage:
    """Test that expected contexts are available."""

    def test_core_html_contexts(self):
        """Test that core HTML contexts are available."""
        contexts = list_contexts()

        assert "html_content" in contexts
        assert "html_attribute" in contexts
        assert "html_comment" in contexts

    def test_javascript_contexts(self):
        """Test that JavaScript contexts are available."""
        contexts = list_contexts()

        assert "javascript" in contexts
        assert "js_string" in contexts
        assert "js_object" in contexts

    def test_advanced_contexts(self):
        """Test that advanced contexts are available."""
        contexts = list_contexts()

        assert "dom_xss" in contexts
        assert "template_injection" in contexts

    def test_default_context(self):
        """Test that default context is available."""
        contexts = list_contexts()
        assert "default" in contexts

    def test_minimum_contexts(self):
        """Test that we have minimum expected number of contexts."""
        contexts = list_contexts()
        assert len(contexts) >= 10  # Should have at least 10 contexts


class TestReverseMapping:
    """Test enhanced reverse mapping functionality."""

    def test_get_reverse_map_info(self):
        """Test reverse mapping system information."""
        info = get_reverse_map_info()

        assert isinstance(info, dict)
        assert "version" in info
        assert "total_patterns" in info
        assert "supported_contexts" in info
        assert "ml_ready" in info

        assert info["version"] == "4.0.0"
        assert info["total_patterns"] > 20
        assert info["ml_ready"] is True
        assert len(info["supported_contexts"]) > 15

    def test_enhanced_payload_analysis(self):
        """Test enhanced payload analysis with confidence scoring."""
        # Test script payload
        result = find_contexts_for_payload("<script>alert(1)</script>")

        assert isinstance(result, dict)
        assert "contexts" in result
        assert "confidence" in result
        assert "analysis_method" in result
        assert "patterns_matched" in result

        # The payload exists in database, so it should find exact match
        assert len(result["contexts"]) > 0
        assert result["confidence"] > 0.8
        assert result["analysis_method"] in ["payload_database", "pattern_matching"]
        assert len(result["patterns_matched"]) > 0

    def test_modern_contexts_detection(self):
        """Test detection of modern XSS contexts."""
        modern_payloads = [
            'WebSocket("wss://evil.com")',
            'serviceWorker.register("evil.js")',
            "RTCPeerConnection({iceServers: []})",
            '{{constructor.constructor("alert(1)")()}}',
        ]

        for payload in modern_payloads:
            result = find_contexts_for_payload(payload)

            assert len(result["contexts"]) > 0
            assert result["confidence"] > 0.8
            # Method can be either 'payload_database' or 'pattern_matching'
            assert result["analysis_method"] in ["payload_database", "pattern_matching"]

    def test_ml_ready_features(self):
        """Test ML-ready feature extraction."""
        payload = "<script>alert(document.cookie)</script>"
        result = predict_contexts_ml_ready(payload)

        assert "features" in result
        assert "ml_ready" in result
        assert "timestamp" in result

        features = result["features"]
        assert "length" in features
        assert "has_script" in features
        assert "special_chars" in features

        assert features["length"] > 0
        assert features["has_script"] is True
        assert features["special_chars"] > 0

        assert result["ml_ready"] is True

    def test_fallback_behavior(self):
        """Test fallback behavior for unknown payloads."""
        # Test empty payload
        result = find_contexts_for_payload("")

        assert result["contexts"] == []
        assert result["analysis_method"] == "none"

        # Test whitespace only
        result = find_contexts_for_payload("   ")

        assert result["contexts"] == []
        assert result["analysis_method"] == "none"

    def test_context_defense_mapping(self):
        """Test that new contexts have proper defense mappings."""
        new_contexts = ["websocket", "service_worker", "webrtc", "webgl"]

        for context in new_contexts:
            from brs_kb.reverse_map import get_defenses_for_context

            defenses = get_defenses_for_context(context)

            assert isinstance(defenses, list)
            assert len(defenses) > 0

            # Check that defenses have required structure
            for defense in defenses:
                assert "defense" in defense
                assert "priority" in defense
                assert "required" in defense
                assert "tags" in defense


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
