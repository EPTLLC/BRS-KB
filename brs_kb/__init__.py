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

import importlib
import os
from typing import Any, Dict, List

# --- Version Information (Single Source of Truth) ---
from brs_kb.version import (
    KB_BUILD,
    KB_REVISION,
    KB_VERSION,
    __author__,
    __build__,
    __license__,
    __revision__,
    __version__,
)


# --- Private variables ---
_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {}
_initialized = False


# --- Private functions ---
def _initialize_knowledge_base():
    """Dynamically load all vulnerability details from contexts directory and subdirectories."""
    global _initialized
    if _initialized:
        return

    contexts_dir = os.path.join(os.path.dirname(__file__), "contexts")

    if not os.path.exists(contexts_dir):
        _initialized = True
        return

    # Import logger for structured logging
    try:
        from brs_kb.logger import get_logger

        logger = get_logger("brs_kb.init")
    except ImportError:
        # Fallback if logger not available
        import logging

        logger = logging.getLogger("brs_kb.init")

    # Load contexts from root directory (base.py, default.py)
    for filename in os.listdir(contexts_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            module_name = filename[:-3]
            _load_context_module(f".contexts.{module_name}", module_name, logger)

    # Load contexts from subdirectories
    subdirs = [
        "html",
        "javascript",
        "dom",
        "frameworks",
        "api",
        "browser",
        "security",
        "injection",
        "other",
    ]
    for subdir in subdirs:
        subdir_path = os.path.join(contexts_dir, subdir)
        if os.path.isdir(subdir_path):
            for filename in os.listdir(subdir_path):
                # Only load main context files (with DETAILS), not _data or _vectors
                if (
                    filename.endswith(".py")
                    and not filename.startswith("__")
                    and not filename.endswith("_data.py")
                    and not filename.endswith("_vectors.py")
                ):
                    module_name = filename[:-3]
                    # Extract context name from brs_kb_ctx_xxx.py -> xxx
                    if module_name.startswith("brs_kb_ctx_"):
                        context_name = module_name[11:]  # Remove "brs_kb_ctx_" prefix
                    else:
                        context_name = module_name
                    _load_context_module(f".contexts.{subdir}.{module_name}", context_name, logger)


def _load_context_module(import_path: str, context_name: str, logger):
    """Load a single context module and register it."""
    global _KNOWLEDGE_BASE
    try:
        module = importlib.import_module(import_path, package=__name__)
        if hasattr(module, "DETAILS"):
            _KNOWLEDGE_BASE[context_name] = module.DETAILS
            logger.debug(
                f"Loaded context: {context_name}",
                extra={"context": context_name},
            )
    except ImportError as e:
        logger.warning(
            f"Failed to import context module: {context_name}",
            extra={"context": context_name, "error": str(e)},
        )
    except Exception as e:
        logger.error(
            f"Unexpected error loading context: {context_name}",
            extra={"context": context_name, "error": str(e)},
            exc_info=True,
        )

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

    Raises:
        ContextNotFoundError: If context not found and default is also unavailable

    Example:
        >>> from brs_kb import get_vulnerability_details
        >>> details = get_vulnerability_details('html_content')
        >>> print(details['title'])
        'Cross-Site Scripting (XSS) in HTML Content'
    """
    import time

    from brs_kb.metrics import record_context_access, record_error

    start_time = time.time()
    _initialize_knowledge_base()

    context = context.lower()
    result = _KNOWLEDGE_BASE.get(context, _KNOWLEDGE_BASE.get("default", {}))

    if not result:
        from brs_kb.exceptions import ContextNotFoundError

        available = list(_KNOWLEDGE_BASE.keys())
        duration = time.time() - start_time
        record_error("context_not_found", context)
        raise ContextNotFoundError(context, available_contexts=available)

    duration = time.time() - start_time
    record_context_access(context, duration)
    return result


def get_kb_version() -> str:
    """Get Knowledge Base version string."""
    return KB_VERSION


def get_kb_info() -> Dict[str, Any]:
    """
    Get comprehensive KB information.

    Returns:
        Dictionary with version, build, revision, total contexts,
        total payloads, author info, and list of available contexts.
    """
    _initialize_knowledge_base()

    # Get payload counts from payloads
    try:
        from brs_kb.payloads import FULL_PAYLOAD_DATABASE

        total_payloads = len(FULL_PAYLOAD_DATABASE)
    except ImportError:
        total_payloads = 0

    return {
        "name": "BRS-KB",
        "full_name": "BRS XSS Knowledge Base",
        "version": KB_VERSION,
        "build": KB_BUILD,
        "revision": KB_REVISION,
        "author": __author__,
        "company": "EasyProTech LLC",
        "website": "https://www.easypro.tech",
        "license": __license__,
        "repo_url": "https://github.com/EPTLLC/BRS-KB",
        "telegram": "https://t.me/EasyProTech",
        "total_contexts": len(_KNOWLEDGE_BASE),
        "total_payloads": total_payloads,
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
    from brs_kb.payloads import get_payloads_by_context as _get_payloads_by_context

    return [_payload_to_dict(p) for p in _get_payloads_by_context(context)]


def get_payloads_by_severity(severity: str) -> List[Dict[str, Any]]:
    """Get all payloads by severity level."""
    from brs_kb.payloads import get_payloads_by_severity as _get_payloads_by_severity

    return [_payload_to_dict(p) for p in _get_payloads_by_severity(severity)]


def get_payloads_by_tag(tag: str) -> List[Dict[str, Any]]:
    """Get all payloads by tag."""
    from brs_kb.payloads import get_payloads_by_tag as _get_payloads_by_tag

    return [_payload_to_dict(p) for p in _get_payloads_by_tag(tag)]


def get_waf_bypass_payloads() -> List[Dict[str, Any]]:
    """Get payloads designed for WAF bypass."""
    from brs_kb.payloads import get_waf_bypass_payloads as _get_waf_bypass_payloads

    return [_payload_to_dict(p) for p in _get_waf_bypass_payloads()]


def get_database_info() -> Dict[str, Any]:
    """Get payload database information."""
    from brs_kb.payloads import get_database_info as _get_database_info

    return _get_database_info()


def search_payloads(query: str) -> List[Dict[str, Any]]:
    """Search payloads by query with relevance scoring."""
    from brs_kb.payloads import search_payloads as _search_payloads

    return [
        {**_payload_to_dict(payload), "relevance_score": score}
        for payload, score in _search_payloads(query)
    ]


def test_payload_effectiveness(payload_id: str, test_context: str) -> Dict[str, Any]:
    """Test payload effectiveness in a specific context."""
    from brs_kb.payloads import test_payload_effectiveness as _test_payload_effectiveness

    return _test_payload_effectiveness(payload_id, test_context)


def get_all_payloads() -> Dict[str, Dict[str, Any]]:
    """Get all payloads in database."""
    from brs_kb.payloads import get_all_payloads as _get_all_payloads

    payloads = _get_all_payloads()
    return {pid: _payload_to_dict(p) for pid, p in payloads.items()}


def add_payload(payload_entry: Dict[str, Any]) -> bool:
    """Add new payload to database."""
    from brs_kb.payloads import PayloadEntry
    from brs_kb.payloads import add_payload as _add_payload

    entry = PayloadEntry(**payload_entry)
    return _add_payload(entry)


def export_payloads(format: str = "json") -> str:
    """Export payloads in specified format."""
    from brs_kb.payloads import export_payloads as _export_payloads

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


# --- Pre-initialize on module load ---
_initialize_knowledge_base()


# Import API server functions
def start_api_server(port: int = 8080, host: str = "0.0.0.0"):
    """Start API server for Web UI integration."""
    from brs_kb.api_server import start_api_server as _start_api_server

    return _start_api_server(port=port, host=host)


def start_metrics_server(port: int = 8000, host: str = "0.0.0.0"):
    """Start Prometheus metrics server."""
    from brs_kb.metrics_server import start_metrics_server as _start_metrics_server

    return _start_metrics_server(port=port, host=host)


# --- Public exports ---
__all__ = [
    "KB_BUILD",
    "KB_REVISION",
    "KB_VERSION",
    "__version__",
    "add_payload",
    # Payload testing
    "analyze_payload_context",
    "export_payloads",
    "find_best_payloads_for_context",
    "generate_payload_report",
    "get_all_contexts",
    "get_all_payloads",
    # CLI functions
    "get_cli",
    "get_database_info",
    "get_kb_info",
    "get_kb_version",
    # Payload database
    "get_payloads_by_context",
    "get_payloads_by_severity",
    "get_payloads_by_tag",
    "get_vulnerability_details",
    "get_waf_bypass_payloads",
    "list_contexts",
    "search_payloads",
    # Server functions
    "start_api_server",
    "start_metrics_server",
    "test_all_payloads",
    "test_payload_effectiveness",
    "validate_payload_database",
]
