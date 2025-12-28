#!/usr/bin/env python3

"""
Tests for payloads/queries.py
Project: BRS-KB
Company: EasyProTech LLC
"""

from brs_kb.payloads import FULL_PAYLOAD_DATABASE
from brs_kb.payloads.models import PayloadEntry
from brs_kb.payloads.queries import (
    get_payload_by_id,
    get_payloads_by_context,
    get_payloads_by_severity,
    get_payloads_by_tag,
    get_waf_bypass_payloads,
)


class TestGetPayloadById:
    """Test get_payload_by_id function"""

    def test_get_payload_by_id_exists(self):
        """Test getting existing payload"""
        if FULL_PAYLOAD_DATABASE:
            payload_id = next(iter(FULL_PAYLOAD_DATABASE.keys()))
            result = get_payload_by_id(payload_id)
            assert result is not None

    def test_get_payload_by_id_not_exists(self):
        """Test getting non-existent payload"""
        result = get_payload_by_id("nonexistent_id_12345")
        assert result is None


class TestGetPayloadsByContext:
    """Test get_payloads_by_context function"""

    def test_get_payloads_by_context_html(self):
        """Test getting payloads for html_content context"""
        results = get_payloads_by_context("html_content")
        assert isinstance(results, list)
        assert len(results) > 0
        for payload in results:
            assert isinstance(payload, PayloadEntry)

    def test_get_payloads_by_context_nonexistent(self):
        """Test getting payloads for non-existent context"""
        results = get_payloads_by_context("nonexistent_context_xyz")
        assert isinstance(results, list)
        assert len(results) == 0


class TestGetPayloadsBySeverity:
    """Test get_payloads_by_severity function"""

    def test_get_payloads_by_severity_critical(self):
        """Test getting critical severity payloads"""
        results = get_payloads_by_severity("critical")
        assert isinstance(results, list)
        assert len(results) > 0
        for payload in results:
            assert payload.severity == "critical"

    def test_get_payloads_by_severity_high(self):
        """Test getting high severity payloads"""
        results = get_payloads_by_severity("high")
        assert isinstance(results, list)

    def test_get_payloads_by_severity_invalid(self):
        """Test getting invalid severity payloads"""
        results = get_payloads_by_severity("invalid_severity")
        assert isinstance(results, list)
        assert len(results) == 0


class TestGetPayloadsByTag:
    """Test get_payloads_by_tag function"""

    def test_get_payloads_by_tag_xss(self):
        """Test getting payloads with xss tag"""
        results = get_payloads_by_tag("xss")
        assert isinstance(results, list)

    def test_get_payloads_by_tag_script(self):
        """Test getting payloads with script tag"""
        results = get_payloads_by_tag("script")
        assert isinstance(results, list)

    def test_get_payloads_by_tag_nonexistent(self):
        """Test getting payloads with non-existent tag"""
        results = get_payloads_by_tag("nonexistent_tag_xyz")
        assert isinstance(results, list)


class TestGetWafBypassPayloads:
    """Test get_waf_bypass_payloads function"""

    def test_get_waf_bypass_payloads_all(self):
        """Test getting all WAF bypass payloads"""
        results = get_waf_bypass_payloads()
        assert isinstance(results, list)
        assert len(results) > 0

    def test_get_waf_bypass_payloads_returns_payloadentry(self):
        """Test that WAF bypass payloads are PayloadEntry objects"""
        results = get_waf_bypass_payloads()
        if results:
            assert isinstance(results[0], PayloadEntry)
