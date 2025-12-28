#!/usr/bin/env python3

"""
Tests for payloads/search.py
"""

from unittest.mock import patch

from brs_kb.payloads.models import PayloadEntry
from brs_kb.payloads.search import search_payloads


class TestSearchPayloads:
    """Test search_payloads function"""

    @patch("brs_kb.metrics.record_search_query")
    def test_search_payloads_basic(self, mock_record):
        """Test search_payloads basic functionality"""
        results = search_payloads("script")
        assert isinstance(results, list)
        assert len(results) > 0
        mock_record.assert_called_once()

    @patch("brs_kb.metrics.record_search_query")
    def test_search_payloads_multiple_queries(self, mock_record):
        """Test search_payloads with different queries"""
        results1 = search_payloads("script")
        results2 = search_payloads("img onerror")
        assert isinstance(results1, list)
        assert isinstance(results2, list)
        # Different queries may return different results
        assert mock_record.call_count == 2

    @patch("brs_kb.metrics.record_search_query")
    def test_search_payloads_returns_payload_entries(self, mock_record):
        """Test search_payloads returns PayloadEntry tuples"""
        results = search_payloads("alert")
        assert isinstance(results, list)
        if results:
            # Each result should be a tuple of (PayloadEntry, score)
            entry, score = results[0]
            assert isinstance(entry, PayloadEntry)
            assert isinstance(score, (int, float))
        mock_record.assert_called_once()

    @patch("brs_kb.metrics.record_search_query")
    def test_search_payloads_empty_query(self, mock_record):
        """Test search_payloads with empty query"""
        results = search_payloads("")
        assert isinstance(results, list)
        mock_record.assert_called_once()

    @patch("brs_kb.metrics.record_search_query")
    def test_search_payloads_no_results(self, mock_record):
        """Test search_payloads with no matches"""
        results = search_payloads("xyznonexistentpattern123456789")
        assert isinstance(results, list)
        assert len(results) == 0
        mock_record.assert_called_once()
