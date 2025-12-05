#!/usr/bin/env python3

"""
Tests for payloads_db/queries.py
"""

import pytest
from unittest.mock import patch, MagicMock
from brs_kb.payloads_db.queries import (
    get_payload_by_id,
    get_payloads_by_context,
    get_payloads_by_severity,
    get_payloads_by_tag,
    get_waf_bypass_payloads,
)
from brs_kb.payloads_db.models import PayloadEntry


class TestGetPayloadById:
    """Test get_payload_by_id function"""

    def test_get_payload_by_id_exists(self):
        """Test getting existing payload"""
        # Get a payload ID from database
        from brs_kb.payloads_db.data import PAYLOAD_DATABASE
        if PAYLOAD_DATABASE:
            payload_id = list(PAYLOAD_DATABASE.keys())[0]
            result = get_payload_by_id(payload_id)
            assert result is not None

    def test_get_payload_by_id_not_exists(self):
        """Test getting non-existent payload"""
        result = get_payload_by_id("nonexistent_id_12345")
        assert result is None


class TestGetPayloadsByContext:
    """Test get_payloads_by_context function"""

    @patch('brs_kb.payloads_db_sqlite.get_database')
    def test_get_payloads_by_context_sqlite(self, mock_get_db):
        """Test get_payloads_by_context with SQLite"""
        mock_db = MagicMock()
        mock_entry = PayloadEntry(
            payload="<script>test</script>",
            contexts=["html_content"],
            severity="critical",
            cvss_score=8.8,
            description="Test"
        )
        mock_db.get_payloads_by_context.return_value = [mock_entry]
        mock_get_db.return_value = mock_db
        
        results = get_payloads_by_context("html_content")
        assert isinstance(results, list)

    def test_get_payloads_by_context_fallback(self):
        """Test get_payloads_by_context fallback"""
        with patch('brs_kb.payloads_db_sqlite.get_database', side_effect=ImportError()):
            results = get_payloads_by_context("html_content")
            assert isinstance(results, list)


class TestGetPayloadsBySeverity:
    """Test get_payloads_by_severity function"""

    @patch('brs_kb.payloads_db_sqlite.get_database')
    def test_get_payloads_by_severity_sqlite(self, mock_get_db):
        """Test get_payloads_by_severity with SQLite"""
        mock_db = MagicMock()
        mock_entry = PayloadEntry(
            payload="<script>test</script>",
            contexts=["html_content"],
            severity="critical",
            cvss_score=8.8,
            description="Test"
        )
        mock_db.get_payloads_by_severity.return_value = [mock_entry]
        mock_get_db.return_value = mock_db
        
        results = get_payloads_by_severity("critical")
        assert isinstance(results, list)

    def test_get_payloads_by_severity_fallback(self):
        """Test get_payloads_by_severity fallback"""
        with patch('brs_kb.payloads_db_sqlite.get_database', side_effect=ImportError()):
            results = get_payloads_by_severity("critical")
            assert isinstance(results, list)


class TestGetPayloadsByTag:
    """Test get_payloads_by_tag function"""

    @patch('brs_kb.payloads_db_sqlite.get_database')
    def test_get_payloads_by_tag_sqlite(self, mock_get_db):
        """Test get_payloads_by_tag with SQLite"""
        mock_db = MagicMock()
        mock_entry = PayloadEntry(
            payload="<script>test</script>",
            contexts=["html_content"],
            severity="critical",
            cvss_score=8.8,
            description="Test",
            tags=["xss"]
        )
        mock_db.get_payloads_by_tag.return_value = [mock_entry]
        mock_get_db.return_value = mock_db
        
        results = get_payloads_by_tag("xss")
        assert isinstance(results, list)

    def test_get_payloads_by_tag_fallback(self):
        """Test get_payloads_by_tag fallback"""
        with patch('brs_kb.payloads_db_sqlite.get_database', side_effect=ImportError()):
            results = get_payloads_by_tag("xss")
            assert isinstance(results, list)


class TestGetWafBypassPayloads:
    """Test get_waf_bypass_payloads function"""

    @patch('brs_kb.payloads_db_sqlite.get_database')
    def test_get_waf_bypass_payloads_sqlite(self, mock_get_db):
        """Test get_waf_bypass_payloads with SQLite"""
        mock_db = MagicMock()
        mock_entry = PayloadEntry(
            payload="<script>test</script>",
            contexts=["html_content"],
            severity="critical",
            cvss_score=8.8,
            description="Test",
            waf_evasion=True
        )
        mock_db.get_waf_bypass_payloads.return_value = [mock_entry]
        mock_get_db.return_value = mock_db
        
        results = get_waf_bypass_payloads()
        assert isinstance(results, list)

    def test_get_waf_bypass_payloads_fallback(self):
        """Test get_waf_bypass_payloads fallback"""
        with patch('brs_kb.payloads_db_sqlite.get_database', side_effect=ImportError()):
            results = get_waf_bypass_payloads()
            assert isinstance(results, list)


