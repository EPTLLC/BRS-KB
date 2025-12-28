#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for validation module
"""

import pytest

from brs_kb.exceptions import ValidationError
from brs_kb.validation import (
    validate_context_details,
    validate_context_name,
    validate_cvss_score,
    validate_limit,
    validate_payload,
    validate_search_query,
    validate_severity,
    validate_tags,
)


class TestValidateContextName:
    """Test context name validation"""

    def test_valid_context_name(self):
        """Test valid context names"""
        assert validate_context_name("html_content") == "html_content"
        assert validate_context_name("HTML_CONTENT") == "html_content"
        assert validate_context_name("  html_content  ") == "html_content"
        assert validate_context_name("js_string") == "js_string"
        assert validate_context_name("context_123") == "context_123"

    def test_invalid_context_name_type(self):
        """Test invalid context name types"""
        with pytest.raises(ValidationError):
            validate_context_name(None)
        with pytest.raises(ValidationError):
            validate_context_name(123)
        with pytest.raises(ValidationError):
            validate_context_name([])

    def test_empty_context_name(self):
        """Test empty context name"""
        with pytest.raises(ValidationError):
            validate_context_name("")
        with pytest.raises(ValidationError):
            validate_context_name("   ")

    def test_invalid_context_name_chars(self):
        """Test invalid characters in context name"""
        with pytest.raises(ValidationError):
            validate_context_name("html-content")
        with pytest.raises(ValidationError):
            validate_context_name("html content")
        with pytest.raises(ValidationError):
            validate_context_name("html@content")

    def test_context_name_too_long(self):
        """Test context name length limit"""
        long_name = "a" * 101
        with pytest.raises(ValidationError):
            validate_context_name(long_name)


class TestValidatePayload:
    """Test payload validation"""

    def test_valid_payload(self):
        """Test valid payloads"""
        assert validate_payload("<script>alert(1)</script>") == "<script>alert(1)</script>"
        assert validate_payload("test") == "test"
        assert validate_payload("  test  ") == "test"

    def test_invalid_payload_type(self):
        """Test invalid payload types"""
        with pytest.raises(ValidationError):
            validate_payload(None)
        with pytest.raises(ValidationError):
            validate_payload(123)
        with pytest.raises(ValidationError):
            validate_payload([])

    def test_empty_payload(self):
        """Test empty payload"""
        with pytest.raises(ValidationError):
            validate_payload("")
        with pytest.raises(ValidationError):
            validate_payload("   ")

    def test_payload_too_long(self):
        """Test payload length limit"""
        long_payload = "a" * 10001
        with pytest.raises(ValidationError):
            validate_payload(long_payload)

    def test_custom_max_length(self):
        """Test custom max length"""
        payload = "a" * 100
        assert validate_payload(payload, max_length=100) == payload
        with pytest.raises(ValidationError):
            validate_payload("a" * 101, max_length=100)


class TestValidateSeverity:
    """Test severity validation"""

    def test_valid_severity(self):
        """Test valid severity levels"""
        assert validate_severity("low") == "low"
        assert validate_severity("LOW") == "low"
        assert validate_severity("  medium  ") == "medium"
        assert validate_severity("high") == "high"
        assert validate_severity("critical") == "critical"

    def test_invalid_severity_type(self):
        """Test invalid severity types"""
        with pytest.raises(ValidationError):
            validate_severity(None)
        with pytest.raises(ValidationError):
            validate_severity(123)

    def test_invalid_severity_value(self):
        """Test invalid severity values"""
        with pytest.raises(ValidationError):
            validate_severity("invalid")
        with pytest.raises(ValidationError):
            validate_severity("info")
        with pytest.raises(ValidationError):
            validate_severity("")


class TestValidateCvssScore:
    """Test CVSS score validation"""

    def test_valid_cvss_score(self):
        """Test valid CVSS scores"""
        assert validate_cvss_score(0.0) == 0.0
        assert validate_cvss_score(5.5) == 5.5
        assert validate_cvss_score(10.0) == 10.0
        assert validate_cvss_score(8) == 8.0

    def test_invalid_cvss_score_type(self):
        """Test invalid CVSS score types"""
        with pytest.raises(ValidationError):
            validate_cvss_score("5.5")
        with pytest.raises(ValidationError):
            validate_cvss_score(None)

    def test_invalid_cvss_score_range(self):
        """Test invalid CVSS score range"""
        with pytest.raises(ValidationError):
            validate_cvss_score(-1.0)
        with pytest.raises(ValidationError):
            validate_cvss_score(10.1)
        with pytest.raises(ValidationError):
            validate_cvss_score(11.0)


class TestValidateTags:
    """Test tags validation"""

    def test_valid_tags(self):
        """Test valid tags"""
        assert validate_tags(["xss", "html"]) == ["xss", "html"]
        assert validate_tags(["tag-1", "tag_2"]) == ["tag-1", "tag_2"]
        assert validate_tags(["  tag  "]) == ["tag"]
        assert validate_tags([]) == []

    def test_invalid_tags_type(self):
        """Test invalid tags types"""
        with pytest.raises(ValidationError):
            validate_tags("not-a-list")
        with pytest.raises(ValidationError):
            validate_tags(None)

    def test_invalid_tag_type(self):
        """Test invalid tag types in list"""
        with pytest.raises(ValidationError):
            validate_tags([123])
        with pytest.raises(ValidationError):
            validate_tags([None])

    def test_empty_tags_filtered(self):
        """Test that empty tags are filtered"""
        assert validate_tags(["tag", "", "   "]) == ["tag"]

    def test_tag_too_long(self):
        """Test tag length limit"""
        long_tag = "a" * 51
        with pytest.raises(ValidationError):
            validate_tags([long_tag])

    def test_invalid_tag_chars(self):
        """Test invalid characters in tags"""
        with pytest.raises(ValidationError):
            validate_tags(["tag@invalid"])
        with pytest.raises(ValidationError):
            validate_tags(["tag invalid"])


class TestValidateSearchQuery:
    """Test search query validation"""

    def test_valid_search_query(self):
        """Test valid search queries"""
        assert validate_search_query("script") == "script"
        assert validate_search_query("  test  ") == "test"
        assert validate_search_query("a") == "a"

    def test_invalid_search_query_type(self):
        """Test invalid search query types"""
        with pytest.raises(ValidationError):
            validate_search_query(None)
        with pytest.raises(ValidationError):
            validate_search_query(123)

    def test_search_query_too_short(self):
        """Test search query minimum length"""
        with pytest.raises(ValidationError):
            validate_search_query("", min_length=1)
        with pytest.raises(ValidationError):
            validate_search_query("a", min_length=2)

    def test_search_query_too_long(self):
        """Test search query maximum length"""
        long_query = "a" * 201
        with pytest.raises(ValidationError):
            validate_search_query(long_query)

    def test_custom_length_limits(self):
        """Test custom length limits"""
        assert validate_search_query("ab", min_length=2, max_length=5) == "ab"
        with pytest.raises(ValidationError):
            validate_search_query("a", min_length=2, max_length=5)
        with pytest.raises(ValidationError):
            validate_search_query("abcdef", min_length=2, max_length=5)


class TestValidateLimit:
    """Test limit validation"""

    def test_valid_limit(self):
        """Test valid limits"""
        assert validate_limit(1) == 1
        assert validate_limit(100) == 100
        assert validate_limit(1000) == 1000

    def test_invalid_limit_type(self):
        """Test invalid limit types"""
        with pytest.raises(ValidationError):
            validate_limit("100")
        with pytest.raises(ValidationError):
            validate_limit(None)

    def test_limit_too_small(self):
        """Test limit minimum value"""
        with pytest.raises(ValidationError):
            validate_limit(0)
        with pytest.raises(ValidationError):
            validate_limit(-1)

    def test_limit_too_large(self):
        """Test limit maximum value"""
        with pytest.raises(ValidationError):
            validate_limit(1001)
        with pytest.raises(ValidationError):
            validate_limit(2000)

    def test_custom_limit_range(self):
        """Test custom limit range"""
        assert validate_limit(5, min_value=1, max_value=10) == 5
        with pytest.raises(ValidationError):
            validate_limit(0, min_value=1, max_value=10)
        with pytest.raises(ValidationError):
            validate_limit(11, min_value=1, max_value=10)


class TestValidateContextDetails:
    """Test context details validation"""

    def test_valid_context_details(self):
        """Test valid context details"""
        details = {
            "title": "Test Context",
            "description": "Test description",
            "attack_vector": "Test attack vector",
            "remediation": "Test remediation",
        }
        result = validate_context_details(details)
        assert result == details

    def test_context_details_with_optional_fields(self):
        """Test context details with optional fields"""
        details = {
            "title": "Test Context",
            "description": "Test description",
            "attack_vector": "Test attack vector",
            "remediation": "Test remediation",
            "severity": "high",
            "cvss_score": 8.5,
            "tags": ["xss", "html"],
        }
        result = validate_context_details(details)
        assert result["severity"] == "high"
        assert result["cvss_score"] == 8.5
        assert result["tags"] == ["xss", "html"]

    def test_invalid_context_details_type(self):
        """Test invalid context details type"""
        with pytest.raises(ValidationError):
            validate_context_details(None)
        with pytest.raises(ValidationError):
            validate_context_details("not-a-dict")
        with pytest.raises(ValidationError):
            validate_context_details([])

    def test_missing_required_fields(self):
        """Test missing required fields"""
        with pytest.raises(ValidationError):
            validate_context_details({})
        with pytest.raises(ValidationError):
            validate_context_details({"title": "Test"})
        with pytest.raises(ValidationError):
            validate_context_details(
                {
                    "title": "Test",
                    "description": "Test",
                }
            )

    def test_empty_required_fields(self):
        """Test empty required fields"""
        with pytest.raises(ValidationError):
            validate_context_details(
                {
                    "title": "",
                    "description": "Test",
                    "attack_vector": "Test",
                    "remediation": "Test",
                }
            )
        with pytest.raises(ValidationError):
            validate_context_details(
                {
                    "title": "Test",
                    "description": "   ",
                    "attack_vector": "Test",
                    "remediation": "Test",
                }
            )

    def test_invalid_optional_fields(self):
        """Test invalid optional fields"""
        details = {
            "title": "Test",
            "description": "Test",
            "attack_vector": "Test",
            "remediation": "Test",
            "severity": "invalid",
        }
        with pytest.raises(ValidationError):
            validate_context_details(details)

        details = {
            "title": "Test",
            "description": "Test",
            "attack_vector": "Test",
            "remediation": "Test",
            "cvss_score": 11.0,
        }
        with pytest.raises(ValidationError):
            validate_context_details(details)

        details = {
            "title": "Test",
            "description": "Test",
            "attack_vector": "Test",
            "remediation": "Test",
            "tags": ["invalid@tag"],
        }
        with pytest.raises(ValidationError):
            validate_context_details(details)
