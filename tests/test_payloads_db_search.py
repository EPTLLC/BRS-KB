#!/usr/bin/env python3

"""
Tests for payloads_db/search.py
"""

import pytest
from unittest.mock import patch, MagicMock
from brs_kb.payloads_db.search import search_payloads
from brs_kb.payloads_db.models import PayloadEntry


class TestSearchPayloads:
    """Test search_payloads function"""

    @patch('brs_kb.payloads_db_sqlite.get_database')
    @patch('brs_kb.metrics.record_search_query')
    def test_search_payloads_sqlite(self, mock_record, mock_get_db):
        """Test search_payloads with SQLite"""
        mock_db = MagicMock()
        mock_entry = PayloadEntry(
            payload="<script>test</script>",
            contexts=["html_content"],
            severity="critical",
            cvss_score=8.8,
            description="Test"
        )
        mock_db.search_payloads.return_value = [(mock_entry, 0.9)]
        mock_get_db.return_value = mock_db
        
        results = search_payloads("script")
        assert isinstance(results, list)
        assert len(results) > 0
        mock_record.assert_called_once()

    @patch('brs_kb.metrics.record_search_query')
    @patch('brs_kb.payload_index.get_index')
    @patch('brs_kb.payloads_db_sqlite.get_database', side_effect=ImportError())
    def test_search_payloads_with_index(self, mock_get_db, mock_get_index, mock_record):
        """Test search_payloads with index"""
        mock_index = MagicMock()
        mock_entry = PayloadEntry(
            payload="<script>test</script>",
            contexts=["html_content"],
            severity="critical",
            cvss_score=8.8,
            description="Test"
        )
        mock_index.search.return_value = [("id1", mock_entry, 0.9)]
        mock_get_index.return_value = mock_index
        
        results = search_payloads("script")
        assert isinstance(results, list)
        mock_record.assert_called_once()

    @patch('brs_kb.metrics.record_search_query')
    @patch('brs_kb.payload_index.get_index', side_effect=ImportError())
    @patch('brs_kb.payloads_db_sqlite.get_database', side_effect=ImportError())
    def test_search_payloads_fallback(self, mock_get_db, mock_get_index, mock_record):
        """Test search_payloads fallback to linear search"""
        results = search_payloads("script")
        assert isinstance(results, list)
        mock_record.assert_called_once()

