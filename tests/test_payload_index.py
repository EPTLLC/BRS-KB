#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for payload_index module
"""

from brs_kb.payload_index import PayloadIndex, get_index, rebuild_index
from brs_kb.payloads import PAYLOAD_DATABASE


class TestPayloadIndex:
    """Test PayloadIndex class"""

    def test_index_initialization(self):
        """Test index initialization"""
        index = PayloadIndex()
        assert not index._initialized
        assert len(index._payload_index) == 0
        assert len(index._description_index) == 0
        assert len(index._tag_index) == 0
        assert len(index._context_index) == 0

    def test_build_indexes(self):
        """Test building indexes"""
        index = PayloadIndex()
        index.build_indexes()

        assert index._initialized
        assert len(index._payload_index) > 0
        assert len(PAYLOAD_DATABASE) > 0

    def test_build_indexes_idempotent(self):
        """Test that build_indexes is idempotent"""
        index = PayloadIndex()
        index.build_indexes()
        first_count = len(index._payload_index)

        index.build_indexes()
        second_count = len(index._payload_index)

        assert first_count == second_count

    def test_tokenize(self):
        """Test tokenization"""
        index = PayloadIndex()
        tokens = index._tokenize("Hello World Test")
        assert "hello" in tokens
        assert "world" in tokens
        assert "test" in tokens

    def test_tokenize_special_chars(self):
        """Test tokenization with special characters"""
        index = PayloadIndex()
        tokens = index._tokenize("<script>alert(1)</script>")
        assert "script" in tokens
        assert "alert" in tokens

    def test_search_basic(self):
        """Test basic search"""
        index = PayloadIndex()
        index.build_indexes()

        results = index.search("script", limit=10)
        assert len(results) > 0
        assert len(results) <= 10

        for payload_id, payload, score in results:
            assert payload_id in PAYLOAD_DATABASE
            assert score > 0
            assert "script" in payload.payload.lower() or score > 0

    def test_search_empty_query(self):
        """Test search with empty query"""
        index = PayloadIndex()
        index.build_indexes()

        results = index.search("", limit=10)
        assert isinstance(results, list)

    def test_search_limit(self):
        """Test search limit"""
        index = PayloadIndex()
        index.build_indexes()

        results = index.search("xss", limit=5)
        assert len(results) <= 5

    def test_search_by_context(self):
        """Test search by context"""
        index = PayloadIndex()
        index.build_indexes()

        results = index.search_by_context("html_content")
        assert len(results) > 0

        for payload in results:
            assert "html_content" in payload.contexts

    def test_search_by_context_invalid(self):
        """Test search by invalid context"""
        index = PayloadIndex()
        index.build_indexes()

        results = index.search_by_context("invalid_context_xyz")
        assert isinstance(results, list)
        assert len(results) == 0

    def test_search_by_tag(self):
        """Test search by tag"""
        index = PayloadIndex()
        index.build_indexes()

        # Find a tag that exists
        if len(index._tag_index) > 0:
            tag = next(iter(index._tag_index.keys()))
            results = index.search_by_tag(tag)
            assert len(results) > 0

    def test_search_by_severity(self):
        """Test search by severity"""
        index = PayloadIndex()
        index.build_indexes()

        results = index.search_by_severity("high")
        assert isinstance(results, list)

        for payload in results:
            assert payload.severity.lower() == "high"

    def test_get_waf_bypass_payloads(self):
        """Test getting WAF bypass payloads"""
        index = PayloadIndex()
        index.build_indexes()

        results = index.get_waf_bypass_payloads()
        assert isinstance(results, list)

        for payload in results:
            assert payload.waf_evasion is True

    def test_get_index_stats(self):
        """Test getting index statistics"""
        index = PayloadIndex()
        index.build_indexes()

        stats = index.get_index_stats()
        assert isinstance(stats, dict)
        assert "payload_words" in stats
        assert "total_payloads" in stats
        assert stats["total_payloads"] == len(PAYLOAD_DATABASE)
        assert stats["total_payloads"] > 0

    def test_rebuild_indexes(self):
        """Test rebuilding indexes"""
        index = PayloadIndex()
        index.build_indexes()
        first_stats = index.get_index_stats()

        index.rebuild_indexes()
        second_stats = index.get_index_stats()

        assert first_stats == second_stats


class TestGetIndex:
    """Test get_index function"""

    def test_get_index_returns_instance(self):
        """Test that get_index returns PayloadIndex instance"""
        index = get_index()
        assert isinstance(index, PayloadIndex)
        assert index._initialized

    def test_get_index_singleton(self):
        """Test that get_index returns same instance"""
        index1 = get_index()
        index2 = get_index()
        assert index1 is index2


class TestRebuildIndex:
    """Test rebuild_index function"""

    def test_rebuild_index(self):
        """Test rebuilding global index"""
        index1 = get_index()
        stats1 = index1.get_index_stats()

        rebuild_index()

        index2 = get_index()
        stats2 = index2.get_index_stats()

        assert stats1 == stats2


class TestIndexSearchScoring:
    """Test search scoring"""

    def test_exact_match_higher_score(self):
        """Test that exact matches get higher scores"""
        index = PayloadIndex()
        index.build_indexes()

        results = index.search("<script>alert(1)</script>", limit=10)
        if len(results) > 0:
            # Exact matches should have higher scores
            exact_matches = [r for r in results if r[1].payload == "<script>alert(1)</script>"]
            if exact_matches:
                exact_score = exact_matches[0][2]
                # Exact match should have high score
                assert exact_score >= 2.0

    def test_token_match_scoring(self):
        """Test token match scoring"""
        index = PayloadIndex()
        index.build_indexes()

        results = index.search("script alert", limit=10)
        assert len(results) > 0

        # Results should be sorted by score (descending)
        scores = [r[2] for r in results]
        assert scores == sorted(scores, reverse=True)
