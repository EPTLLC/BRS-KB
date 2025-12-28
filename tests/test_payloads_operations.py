#!/usr/bin/env python3

"""
Tests for payloads/operations.py
Project: BRS-KB
Company: EasyProTech LLC
"""

from brs_kb.payloads.models import PayloadEntry
from brs_kb.payloads.operations import add_payload, export_payloads, get_all_payloads


class TestGetAllPayloads:
    """Test get_all_payloads function"""

    def test_get_all_payloads_returns_dict(self):
        """Test that get_all_payloads returns a dictionary"""
        result = get_all_payloads()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_get_all_payloads_contains_payloadentry(self):
        """Test that payloads are PayloadEntry objects"""
        result = get_all_payloads()
        if result:
            first_key = next(iter(result.keys()))
            assert isinstance(result[first_key], PayloadEntry)


class TestAddPayload:
    """Test add_payload function"""

    def test_add_payload_returns_bool(self):
        """Test that add_payload returns boolean"""
        entry = PayloadEntry(
            payload="<test>payload</test>",
            contexts=["test_context"],
            severity="low",
            cvss_score=1.0,
            description="Test payload",
        )
        result = add_payload(entry)
        assert isinstance(result, bool)


class TestExportPayloads:
    """Test export_payloads function"""

    def test_export_payloads_json(self):
        """Test exporting payloads as JSON"""
        result = export_payloads(format="json")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_export_payloads_csv(self):
        """Test exporting payloads as CSV"""
        result = export_payloads(format="csv")
        assert isinstance(result, str)
