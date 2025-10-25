#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-14 22:53:00 MSK
Status: Created
Telegram: https://t.me/easyprotech

BRS-KB: Community-Driven XSS Knowledge Base
Open Knowledge for Security Community
"""

import os
import importlib
from typing import Dict, Any, List

# --- Version Information ---
__version__ = "2.0.0"
__build__ = "2025.10.25"
__revision__ = "enhanced"
__author__ = "Brabus / EasyProTech LLC"
__license__ = "MIT"

KB_VERSION = __version__
KB_BUILD = __build__
KB_REVISION = __revision__

# --- Private variables ---
_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {}
_initialized = False


# --- Private functions ---
def _initialize_knowledge_base():
    """Dynamically load all vulnerability details from contexts directory."""
    global _initialized
    if _initialized:
        return

    contexts_dir = os.path.join(os.path.dirname(__file__), "contexts")

    if not os.path.exists(contexts_dir):
        _initialized = True
        return

    for filename in os.listdir(contexts_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            module_name = filename[:-3]

            try:
                module = importlib.import_module(f".contexts.{module_name}", package=__name__)
                if hasattr(module, "DETAILS"):
                    _KNOWLEDGE_BASE[module_name] = module.DETAILS
            except ImportError:
                continue

    _initialized = True


# --- Public API ---
def get_vulnerability_details(context: str) -> Dict[str, Any]:
    """
    Retrieves vulnerability details for a given context.

    Args:
        context: The vulnerability context name (e.g., 'html_content', 'dom_xss')

    Returns:
        Dictionary with vulnerability details including title, description,
        attack_vector, remediation, and metadata (severity, CVSS, CWE, etc.)

    Example:
        >>> from brs_kb import get_vulnerability_details
        >>> details = get_vulnerability_details('html_content')
        >>> print(details['title'])
        'Cross-Site Scripting (XSS) in HTML Content'
    """
    _initialize_knowledge_base()

    context = context.lower()
    return _KNOWLEDGE_BASE.get(context, _KNOWLEDGE_BASE.get("default", {}))


def get_kb_version() -> str:
    """Get Knowledge Base version string."""
    return KB_VERSION


def get_kb_info() -> Dict[str, Any]:
    """
    Get comprehensive KB information.

    Returns:
        Dictionary with version, build, revision, total contexts,
        and list of available contexts.
    """
    _initialize_knowledge_base()
    return {
        "version": KB_VERSION,
        "build": KB_BUILD,
        "revision": KB_REVISION,
        "total_contexts": len(_KNOWLEDGE_BASE),
        "available_contexts": sorted(_KNOWLEDGE_BASE.keys()),
    }


def list_contexts() -> List[str]:
    """
    List all available vulnerability contexts.

    Returns:
        Sorted list of context names.
    """
    _initialize_knowledge_base()
    return sorted(_KNOWLEDGE_BASE.keys())


def get_all_contexts() -> Dict[str, Dict[str, Any]]:
    """
    Get all contexts with their details.

    Returns:
        Dictionary mapping context names to their details.
    """
    _initialize_knowledge_base()
    return _KNOWLEDGE_BASE.copy()


# Import payload database functions
def get_payloads_by_context(context: str) -> List[Dict[str, Any]]:
    """Get all payloads effective in a specific context."""
    from brs_kb.payloads_db import get_payloads_by_context as _get_payloads_by_context

    return [_payload_to_dict(p) for p in _get_payloads_by_context(context)]


def get_payloads_by_severity(severity: str) -> List[Dict[str, Any]]:
    """Get all payloads by severity level."""
    from brs_kb.payloads_db import get_payloads_by_severity as _get_payloads_by_severity

    return [_payload_to_dict(p) for p in _get_payloads_by_severity(severity)]


def get_payloads_by_tag(tag: str) -> List[Dict[str, Any]]:
    """Get all payloads by tag."""
    from brs_kb.payloads_db import get_payloads_by_tag as _get_payloads_by_tag

    return [_payload_to_dict(p) for p in _get_payloads_by_tag(tag)]


def get_waf_bypass_payloads() -> List[Dict[str, Any]]:
    """Get payloads designed for WAF bypass."""
    from brs_kb.payloads_db import get_waf_bypass_payloads as _get_waf_bypass_payloads

    return [_payload_to_dict(p) for p in _get_waf_bypass_payloads()]


def get_database_info() -> Dict[str, Any]:
    """Get payload database information."""
    from brs_kb.payloads_db import get_database_info as _get_database_info

    return _get_database_info()


def search_payloads(query: str) -> List[Dict[str, Any]]:
    """Search payloads by query with relevance scoring."""
    from brs_kb.payloads_db import search_payloads as _search_payloads

    return [
        {**_payload_to_dict(payload), "relevance_score": score}
        for payload, score in _search_payloads(query)
    ]


def test_payload_effectiveness(payload_id: str, test_context: str) -> Dict[str, Any]:
    """Test payload effectiveness in a specific context."""
    from brs_kb.payloads_db import test_payload_effectiveness as _test_payload_effectiveness

    return _test_payload_effectiveness(payload_id, test_context)


def get_all_payloads() -> Dict[str, Dict[str, Any]]:
    """Get all payloads in database."""
    from brs_kb.payloads_db import get_all_payloads as _get_all_payloads

    payloads = _get_all_payloads()
    return {pid: _payload_to_dict(p) for pid, p in payloads.items()}


def add_payload(payload_entry: Dict[str, Any]) -> bool:
    """Add new payload to database."""
    from brs_kb.payloads_db import PayloadEntry, add_payload as _add_payload

    entry = PayloadEntry(**payload_entry)
    return _add_payload(entry)


def export_payloads(format: str = "json") -> str:
    """Export payloads in specified format."""
    from brs_kb.payloads_db import export_payloads as _export_payloads

    return _export_payloads(format)


# Import payload testing functions
def analyze_payload_context(payload: str, context: str) -> Dict[str, Any]:
    """Test payload effectiveness in specific context."""
    from brs_kb.payload_testing import PayloadTester

    tester = PayloadTester()
    return tester.test_payload_in_context(payload, context)


def test_all_payloads() -> Dict[str, Any]:
    """Test all payloads in database."""
    from brs_kb.payload_testing import test_all_payloads as _test_all_payloads

    return _test_all_payloads()


def validate_payload_database() -> Dict[str, Any]:
    """Validate payload database integrity."""
    from brs_kb.payload_testing import validate_payload_database as _validate_payload_database

    return _validate_payload_database()


def generate_payload_report() -> str:
    """Generate comprehensive payload analysis report."""
    from brs_kb.payload_testing import generate_payload_report as _generate_payload_report

    return _generate_payload_report()


def find_best_payloads_for_context(
    context: str, min_effectiveness: float = 0.5
) -> List[Dict[str, Any]]:
    """Find best payloads for a specific context."""
    from brs_kb.payload_testing import (
        find_best_payloads_for_context as _find_best_payloads_for_context,
    )

    return _find_best_payloads_for_context(context, min_effectiveness)


def _payload_to_dict(payload_entry) -> Dict[str, Any]:
    """Convert PayloadEntry to dictionary."""
    return {
        "payload": payload_entry.payload,
        "contexts": payload_entry.contexts,
        "severity": payload_entry.severity,
        "cvss_score": payload_entry.cvss_score,
        "description": payload_entry.description,
        "tags": payload_entry.tags,
        "bypasses": payload_entry.bypasses,
        "encoding": payload_entry.encoding,
        "browser_support": payload_entry.browser_support,
        "waf_evasion": payload_entry.waf_evasion,
        "tested_on": payload_entry.tested_on,
        "reliability": payload_entry.reliability,
        "last_updated": payload_entry.last_updated,
    }


# Import CLI class
def get_cli():
    """Get CLI instance for programmatic use."""
    from brs_kb.cli import BRSKBCLI

    return BRSKBCLI()


# Import localization functions
def set_language(language: str) -> bool:
    """Set global language."""
    from brs_kb.i18n import set_language as _set_language

    return _set_language(language)


def get_current_language() -> str:
    """Get current language."""
    from brs_kb.i18n import get_current_language as _get_current_language

    return _get_current_language()


def get_supported_languages() -> List[str]:
    """Get supported languages."""
    from brs_kb.i18n import get_supported_languages as _get_supported_languages

    return _get_supported_languages()


def get_localized_context(context_id: str) -> Dict[str, Any]:
    """Get localized context."""
    from brs_kb.i18n import get_context_details as _get_context_details

    return _get_context_details(context_id)


def get_localized_string(key: str) -> str:
    """Get localized string."""
    from brs_kb.i18n import t as _t

    return _t(key)


def get_available_contexts_localized() -> List[Dict[str, Any]]:
    """Get localized contexts."""
    # This function is not directly available in new i18n system
    # Return empty list for backward compatibility
    return []


# --- Pre-initialize on module load ---
_initialize_knowledge_base()

# --- Public exports ---
__all__ = [
    "get_vulnerability_details",
    "get_kb_version",
    "get_kb_info",
    "list_contexts",
    "get_all_contexts",
    "KB_VERSION",
    "KB_BUILD",
    "KB_REVISION",
    "__version__",
    # Payload database
    "get_payloads_by_context",
    "get_payloads_by_severity",
    "get_payloads_by_tag",
    "get_waf_bypass_payloads",
    "get_database_info",
    "search_payloads",
    "test_payload_effectiveness",
    "get_all_payloads",
    "add_payload",
    "export_payloads",
    # Payload testing
    "analyze_payload_context",
    "test_all_payloads",
    "validate_payload_database",
    "generate_payload_report",
    "find_best_payloads_for_context",
    # CLI functions
    "BRSKBCLI",
    "get_cli",
    # Localization functions
    "set_language",
    "get_current_language",
    "get_supported_languages",
    "get_localized_context",
    "get_localized_string",
    "get_available_contexts_localized",
]
