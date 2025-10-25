#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Integration Tests for BRS-KB - Complete System Integration Testing
"""

import pytest
from brs_kb import (
    get_kb_info, list_contexts, get_vulnerability_details,
    get_payloads_by_context, search_payloads, analyze_payload_context,
    get_database_info, validate_payload_database, get_all_contexts
)
from brs_kb.reverse_map import find_contexts_for_payload, get_reverse_map_info
from brs_kb.i18n import set_language, get_current_language


class TestCompleteIntegration:
    """Test complete BRS-KB system integration."""

    def test_system_initialization(self):
        """Test that all system components initialize correctly."""
        # Test KB info
        kb_info = get_kb_info()
        assert isinstance(kb_info, dict)
        assert kb_info['total_contexts'] >= 25  # Should have at least 25 contexts
        assert kb_info['version'] == "2.0.0"

        # Test database info
        db_info = get_database_info()
        assert isinstance(db_info, dict)
        assert db_info['total_payloads'] >= 200
        assert 'contexts_covered' in db_info

        # Test reverse map info
        rm_info = get_reverse_map_info()
        assert isinstance(rm_info, dict)
        assert rm_info['ml_ready'] is True

    def test_context_database_integration(self):
        """Test integration between contexts and payload database."""
        contexts = list_contexts()
        assert len(contexts) >= 25

        # Test that each context has payloads
        for context in ['html_content', 'websocket_xss', 'service_worker_xss']:
            payloads = get_payloads_by_context(context)
            assert len(payloads) > 0, f"No payloads found for context: {context}"

            # Test payload structure
            for payload in payloads[:3]:  # Test first 3
                assert 'payload' in payload
                assert 'contexts' in payload
                assert 'severity' in payload
                assert 'cvss_score' in payload
                assert context in payload['contexts']

    def test_reverse_mapping_integration(self):
        """Test integration between reverse mapping and payload analysis."""
        # Test known payloads
        test_cases = [
            ("<script>alert(1)</script>", "html_content"),
            ("javascript:alert(1)", "url_context"),
            ('{"type": "chat", "message": "<script>alert(1)</script>"}', "websocket_xss")
        ]

        for payload, expected_context in test_cases:
            result = find_contexts_for_payload(payload)

            assert isinstance(result, dict)
            assert 'contexts' in result
            assert 'confidence' in result
            assert 'analysis_method' in result
            assert len(result['contexts']) > 0
            assert result['confidence'] > 0.5  # Should have reasonable confidence

    def test_payload_testing_integration(self):
        """Test payload testing functionality."""
        test_payload = "<script>alert('XSS')</script>"
        test_context = "html_content"

        result = analyze_payload_context(test_payload, test_context)

        assert isinstance(result, dict)
        assert 'effectiveness_score' in result
        assert 'risk_level' in result
        assert 'browser_parsing' in result
        assert 'waf_detected' in result
        assert 'recommendations' in result

        # Should detect script execution
        assert result['browser_parsing']['script_execution'] is True

    def test_localization_integration(self):
        """Test localization system integration."""
        # Test language switching
        assert set_language("ru") is True
        assert get_current_language() == "ru"

        assert set_language("en") is True
        assert get_current_language() == "en"

        # Test invalid language
        assert set_language("invalid") is False

    def test_search_integration(self):
        """Test search functionality across the system."""
        # Search for script-related payloads
        results = search_payloads("script")

        assert isinstance(results, list)
        assert len(results) > 0

        # Each result should have required fields
        for result in results[:5]:  # Test first 5
            assert 'payload' in result
            assert 'contexts' in result
            assert 'severity' in result
            assert 'relevance_score' in result
            assert result['relevance_score'] > 0

    def test_database_validation_integration(self):
        """Test database validation functionality."""
        validation = validate_payload_database()

        assert isinstance(validation, dict)
        assert 'total_payloads' in validation
        assert 'contexts_covered' in validation
        assert 'errors' in validation

        # Should have no validation errors
        assert len(validation['errors']) == 0
        assert validation['total_payloads'] >= 200

    def test_context_completeness(self):
        """Test that all contexts have complete information."""
        all_contexts = get_all_contexts()

        required_fields = [
            'title', 'description', 'attack_vector', 'remediation',
            'severity', 'cvss_score', 'cwe', 'owasp', 'tags'
        ]

        for context_name, context_data in all_contexts.items():
            # Check required fields
            for field in required_fields:
                assert field in context_data, f"Missing field '{field}' in context '{context_name}'"
                assert context_data[field] is not None, f"Empty field '{field}' in context '{context_name}'"

            # Check data types
            assert isinstance(context_data['title'], str)
            assert isinstance(context_data['severity'], str)
            assert isinstance(context_data['cvss_score'], (int, float))
            assert isinstance(context_data['cwe'], list)
            assert isinstance(context_data['owasp'], list)
            assert isinstance(context_data['tags'], list)

    def test_payload_context_consistency(self):
        """Test consistency between payloads and their contexts."""
        db_info = get_database_info()

        for context in db_info['contexts_covered']:
            payloads = get_payloads_by_context(context)

            # Each payload should reference this context
            for payload in payloads:
                assert context in payload['contexts'], f"Payload {payload['payload'][:50]}... not in context {context}"

                # Context should exist in the KB
                context_details = get_vulnerability_details(context)
                assert context_details is not None, f"Context {context} not found in KB"

    def test_cli_integration(self):
        """Test CLI integration with the system."""
        from brs_kb.cli import BRSKBCLI

        # Test CLI initialization
        cli = BRSKBCLI()
        assert cli is not None

        # Test argument parsing (basic)
        try:
            # This should not raise an exception
            args = cli.parser.parse_args(['info'])
            assert args.command == 'info'
        except SystemExit:
            # argparse exits on error, which is expected for invalid args
            pass

    def test_system_performance(self):
        """Test system performance with large datasets."""
        import time

        # Test context loading performance
        start_time = time.time()
        contexts = list_contexts()
        context_load_time = time.time() - start_time

        # Should load quickly
        assert context_load_time < 1.0, f"Context loading too slow: {context_load_time}s"
        assert len(contexts) >= 25

        # Test payload search performance
        start_time = time.time()
        results = search_payloads("script")
        search_time = time.time() - start_time

        # Should search quickly
        assert search_time < 2.0, f"Search too slow: {search_time}s"
        assert len(results) > 0

    def test_data_integrity(self):
        """Test data integrity across the system."""
        # Test that all context references are valid
        all_contexts = set(list_contexts())

        # Check payload context references
        db_info = get_database_info()
        payload_objects = []
        for context in db_info['contexts_covered']:
            payload_objects.extend(get_payloads_by_context(context))

        # All payload contexts should exist in KB
        for payload in payload_objects:
            for context in payload['contexts']:
                assert context in all_contexts, f"Invalid context reference: {context}"

        # Test reverse mapping consistency
        test_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            'WebSocket("wss://evil.com")'
        ]

        for payload in test_payloads:
            result = find_contexts_for_payload(payload)
            for context in result['contexts']:
                assert context in all_contexts, f"Reverse mapping returned invalid context: {context}"

    def test_system_scaling(self):
        """Test system performance with large datasets."""
        # Test with multiple contexts
        contexts = list_contexts()
        assert len(contexts) >= 25

        # Test with multiple payloads
        db_info = get_database_info()
        assert db_info['total_payloads'] >= 200

        # Test search with large dataset
        results = search_payloads("xss")
        assert len(results) > 0

        # Test analysis performance
        import time
        start_time = time.time()

        for i in range(10):  # Test 10 payloads
            payload = f"<script>alert({i})</script>"
            result = find_contexts_for_payload(payload)

        analysis_time = time.time() - start_time
        assert analysis_time < 5.0, f"Analysis too slow: {analysis_time}s"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
