#!/usr/bin/env python3

"""
Tests for payloads_db/operations.py
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from brs_kb.payloads_db.operations import get_all_payloads, add_payload, export_payloads
from brs_kb.payloads_db.models import PayloadEntry


class TestGetAllPayloads:
    """Test get_all_payloads function"""

    @patch('brs_kb.payloads_db_sqlite.get_database')
    def test_get_all_payloads_sqlite(self, mock_get_db):
        """Test get_all_payloads with SQLite"""
        mock_db = MagicMock()
        mock_entry = PayloadEntry(
            payload="<script>test</script>",
            contexts=["html_content"],
            severity="critical",
            cvss_score=8.8,
            description="Test"
        )
        mock_db.get_all_payloads.return_value = [mock_entry]
        mock_get_db.return_value = mock_db
        
        result = get_all_payloads()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_get_all_payloads_fallback(self):
        """Test get_all_payloads fallback to in-memory"""
        with patch('brs_kb.payloads_db_sqlite.get_database', side_effect=ImportError()):
            result = get_all_payloads()
            assert isinstance(result, dict)


class TestAddPayload:
    """Test add_payload function"""

    def test_add_payload_success(self):
        """Test adding a new payload"""
        entry = PayloadEntry(
            payload="<test>new_payload</test>",
            contexts=["html_content"],
            severity="high",
            cvss_score=7.5,
            description="New test payload"
        )
        
        with patch('brs_kb.payload_index.rebuild_index'):
            result = add_payload(entry)
            assert result is True

    def test_add_payload_duplicate(self):
        """Test adding duplicate payload"""
        # First add
        entry = PayloadEntry(
            payload="<duplicate>test</duplicate>",
            contexts=["html_content"],
            severity="high",
            cvss_score=7.5,
            description="Duplicate test"
        )
        
        with patch('brs_kb.payload_index.rebuild_index'):
            add_payload(entry)
            # Try to add again
            result = add_payload(entry)
            assert result is False

    def test_add_payload_no_index(self):
        """Test add_payload when index is not available"""
        entry = PayloadEntry(
            payload="<no_index>test</no_index>",
            contexts=["html_content"],
            severity="high",
            cvss_score=7.5,
            description="No index test"
        )
        
        with patch('brs_kb.payload_index.rebuild_index', side_effect=ImportError()):
            result = add_payload(entry)
            assert result is True


class TestExportPayloads:
    """Test export_payloads function"""

    def test_export_payloads_json(self):
        """Test exporting payloads as JSON"""
        result = export_payloads("json")
        assert isinstance(result, str)
        # Should be valid JSON
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_export_payloads_unsupported_format(self):
        """Test exporting with unsupported format"""
        result = export_payloads("xml")
        assert result == "Unsupported format"


