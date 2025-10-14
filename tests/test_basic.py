#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-14 22:53:00 MSK
Status: Created
Telegram: https://t.me/easyprotech

Basic Tests for BRS-KB
"""

import pytest
from brs_kb import (
    get_vulnerability_details,
    get_kb_info,
    list_contexts,
    get_kb_version,
    get_all_contexts,
    __version__
)


class TestBasicFunctionality:
    """Test basic BRS-KB functionality."""
    
    def test_version_available(self):
        """Test that version is available."""
        assert __version__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0
    
    def test_get_kb_version(self):
        """Test getting KB version."""
        version = get_kb_version()
        assert version is not None
        assert isinstance(version, str)
        assert version == __version__
    
    def test_get_kb_info(self):
        """Test getting KB information."""
        info = get_kb_info()
        
        assert isinstance(info, dict)
        assert 'version' in info
        assert 'build' in info
        assert 'revision' in info
        assert 'total_contexts' in info
        assert 'available_contexts' in info
        
        assert info['total_contexts'] > 0
        assert isinstance(info['available_contexts'], list)
    
    def test_list_contexts(self):
        """Test listing all contexts."""
        contexts = list_contexts()
        
        assert isinstance(contexts, list)
        assert len(contexts) > 0
        assert 'html_content' in contexts
        assert 'default' in contexts
    
    def test_get_all_contexts(self):
        """Test getting all contexts with details."""
        all_contexts = get_all_contexts()
        
        assert isinstance(all_contexts, dict)
        assert len(all_contexts) > 0
        
        # Check that each context has details
        for context_name, details in all_contexts.items():
            assert isinstance(details, dict)
            assert 'title' in details


class TestVulnerabilityDetails:
    """Test vulnerability details retrieval."""
    
    def test_get_known_context(self):
        """Test getting details for known context."""
        details = get_vulnerability_details('html_content')
        
        assert isinstance(details, dict)
        assert 'title' in details
        assert 'description' in details
        assert 'attack_vector' in details
        assert 'remediation' in details
    
    def test_get_unknown_context(self):
        """Test getting details for unknown context (should return default)."""
        details = get_vulnerability_details('totally_unknown_context_xyz')
        
        assert isinstance(details, dict)
        assert len(details) > 0  # Should return default, not empty
    
    def test_context_metadata(self):
        """Test that contexts have proper metadata."""
        details = get_vulnerability_details('html_content')
        
        # Check for metadata fields (if present)
        if 'severity' in details:
            assert details['severity'] in ['low', 'medium', 'high', 'critical']
        
        if 'cvss_score' in details:
            assert 0.0 <= details['cvss_score'] <= 10.0
        
        if 'cwe' in details:
            assert isinstance(details['cwe'], list)
        
        if 'tags' in details:
            assert isinstance(details['tags'], list)
    
    def test_required_fields(self):
        """Test that required fields are present."""
        details = get_vulnerability_details('html_content')
        
        # Required fields
        assert 'title' in details
        assert 'description' in details
        assert 'attack_vector' in details
        assert 'remediation' in details
        
        # Check that they're not empty
        assert len(details['title']) > 0
        assert len(details['description']) > 0
        assert len(details['attack_vector']) > 0
        assert len(details['remediation']) > 0


class TestContextCoverage:
    """Test that expected contexts are available."""
    
    def test_core_html_contexts(self):
        """Test that core HTML contexts are available."""
        contexts = list_contexts()
        
        assert 'html_content' in contexts
        assert 'html_attribute' in contexts
        assert 'html_comment' in contexts
    
    def test_javascript_contexts(self):
        """Test that JavaScript contexts are available."""
        contexts = list_contexts()
        
        assert 'javascript_context' in contexts
        assert 'js_string' in contexts
        assert 'js_object' in contexts
    
    def test_advanced_contexts(self):
        """Test that advanced contexts are available."""
        contexts = list_contexts()
        
        assert 'dom_xss' in contexts
        assert 'template_injection' in contexts
    
    def test_default_context(self):
        """Test that default context is available."""
        contexts = list_contexts()
        assert 'default' in contexts
    
    def test_minimum_contexts(self):
        """Test that we have minimum expected number of contexts."""
        contexts = list_contexts()
        assert len(contexts) >= 10  # Should have at least 10 contexts


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

