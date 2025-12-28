#!/usr/bin/env python3

"""
Tests for payloads/testing.py
"""

import pytest

import brs_kb.payloads.testing as testing_module
from brs_kb.payloads import PAYLOAD_DATABASE


class TestTestPayloadEffectiveness:
    """Test test_payload_effectiveness function"""

    def test_test_payload_effectiveness_success(self):
        """Test payload effectiveness with valid payload and context"""
        if not PAYLOAD_DATABASE:
            pytest.skip("No payloads in database")

        payload_id = next(iter(PAYLOAD_DATABASE.keys()))
        payload = PAYLOAD_DATABASE[payload_id]

        if payload.contexts:
            context = payload.contexts[0]
            result = testing_module.test_payload_effectiveness(payload_id, context)

            assert isinstance(result, dict)
            assert "payload_id" in result
            assert "payload" in result
            assert "context" in result
            assert "is_effective" in result
            assert "confidence" in result
            assert result["is_effective"] is True
            assert result["confidence"] == 1.0

    def test_test_payload_effectiveness_not_found(self):
        """Test payload effectiveness with non-existent payload"""
        result = testing_module.test_payload_effectiveness("nonexistent_id_12345", "html_content")
        assert isinstance(result, dict)
        assert "error" in result
        assert result["error"] == "Payload not found"

    def test_test_payload_effectiveness_wrong_context(self):
        """Test payload effectiveness with wrong context"""
        if not PAYLOAD_DATABASE:
            pytest.skip("No payloads in database")

        payload_id = next(iter(PAYLOAD_DATABASE.keys()))
        result = testing_module.test_payload_effectiveness(payload_id, "nonexistent_context_12345")

        assert isinstance(result, dict)
        assert "is_effective" in result
        assert result["is_effective"] is False
        assert result["confidence"] == 0.0
