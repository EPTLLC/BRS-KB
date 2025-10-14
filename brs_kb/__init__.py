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
__version__ = "1.0.0"
__build__ = "2025.10.14"
__revision__ = "stable"
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
    global _KNOWLEDGE_BASE, _initialized
    if _initialized:
        return

    contexts_dir = os.path.join(os.path.dirname(__file__), 'contexts')
    
    if not os.path.exists(contexts_dir):
        _initialized = True
        return
    
    for filename in os.listdir(contexts_dir):
        if filename.endswith('.py') and not filename.startswith('__'):
            module_name = filename[:-3]
            
            try:
                module = importlib.import_module(f".contexts.{module_name}", package=__name__)
                if hasattr(module, 'DETAILS'):
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
        "available_contexts": sorted(_KNOWLEDGE_BASE.keys())
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

# --- Pre-initialize on module load ---
_initialize_knowledge_base()

# --- Public exports ---
__all__ = [
    'get_vulnerability_details',
    'get_kb_version',
    'get_kb_info',
    'list_contexts',
    'get_all_contexts',
    'KB_VERSION',
    'KB_BUILD',
    'KB_REVISION',
    '__version__'
]

