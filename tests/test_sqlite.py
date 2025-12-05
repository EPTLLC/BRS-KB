#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Tests for SQLite database module
"""

import os
import tempfile
import pytest
from brs_kb.payloads_db import PayloadEntry, PAYLOAD_DATABASE
from brs_kb.payloads_db_sqlite import PayloadDatabase, get_database


class TestSQLiteDatabase:
    """Test SQLite database operations"""

    def test_database_creation(self):
        """Test database creation"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            db = PayloadDatabase(db_path)
            assert db is not None
            assert os.path.exists(db_path)
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_add_payload(self):
        """Test adding payload to database"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            db = PayloadDatabase(db_path)
            payload = PayloadEntry(
                payload="<script>test</script>",
                contexts=["html_content"],
                severity="critical",
                cvss_score=9.0,
                description="Test payload",
            )
            result = db.add_payload(payload)
            assert result is not None
            
            stats = db.get_stats()
            assert stats['total_payloads'] >= 1
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_search_payloads(self):
        """Test searching payloads"""
        db = get_database()
        results = db.search_payloads("script")
        assert isinstance(results, list)
        assert len(results) > 0

    def test_get_payloads_by_context(self):
        """Test getting payloads by context"""
        db = get_database()
        results = db.get_payloads_by_context("html_content")
        assert isinstance(results, list)
        assert len(results) > 0

    def test_get_payloads_by_severity(self):
        """Test getting payloads by severity"""
        db = get_database()
        results = db.get_payloads_by_severity("critical")
        assert isinstance(results, list)

    def test_get_payloads_by_tag(self):
        """Test getting payloads by tag"""
        db = get_database()
        results = db.get_payloads_by_tag("script")
        assert isinstance(results, list)

    def test_get_waf_bypass_payloads(self):
        """Test getting WAF bypass payloads"""
        db = get_database()
        results = db.get_waf_bypass_payloads()
        assert isinstance(results, list)

    def test_get_stats(self):
        """Test getting database statistics"""
        db = get_database()
        stats = db.get_stats()
        assert isinstance(stats, dict)
        assert 'total_payloads' in stats
        assert stats['total_payloads'] >= 0

    def test_migrate_from_memory(self):
        """Test migration from in-memory database"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            db = PayloadDatabase(db_path)
            # Create test payloads
            test_payloads = {
                "test1": PayloadEntry(
                    payload="<script>test1</script>",
                    contexts=["html_content"],
                    severity="critical",
                    cvss_score=9.0,
                    description="Test 1",
                ),
                "test2": PayloadEntry(
                    payload="<img src=x onerror=alert(1)>",
                    contexts=["html_attribute"],
                    severity="high",
                    cvss_score=7.5,
                    description="Test 2",
                ),
            }
            
            db.migrate_from_memory(test_payloads)
            stats = db.get_stats()
            assert stats['total_payloads'] >= 2
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_get_all_payloads(self):
        """Test getting all payloads"""
        db = get_database()
        all_payloads = db.get_all_payloads()
        assert isinstance(all_payloads, list)
        assert len(all_payloads) > 0

    def test_payload_roundtrip(self):
        """Test payload roundtrip (add -> search)"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            db = PayloadDatabase(db_path)
            payload = PayloadEntry(
                payload="<script>roundtrip</script>",
                contexts=["html_content"],
                severity="critical",
                cvss_score=9.0,
                description="Roundtrip test",
                tags=["test", "roundtrip"],
            )
            
            payload_id = db.add_payload(payload)
            assert payload_id is not None
            
            # Search for the payload we just added
            results = db.search_payloads("roundtrip")
            assert len(results) > 0
            retrieved = results[0][0]  # First result, payload entry
            
            assert retrieved.payload == payload.payload
            assert retrieved.contexts == payload.contexts
            assert retrieved.severity == payload.severity
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

