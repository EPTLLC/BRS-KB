#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-25 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Single Source of Truth for all version information.
All modules MUST import version from here.
"""

# =============================================================================
# VERSION - Single Source of Truth
# =============================================================================
# Change version ONLY here. All other modules import from this file.

__version__ = "4.0.0"
__build__ = "2025.12.27"
__revision__ = "production"

# Aliases for backward compatibility
VERSION = __version__
KB_VERSION = __version__
KB_BUILD = __build__
KB_REVISION = __revision__

# Component versions (all equal to main version for consistency)
PAYLOAD_DB_VERSION = __version__
EXTENDED_DB_VERSION = __version__
REVERSE_MAP_VERSION = __version__

# Metadata
__author__ = "Brabus / EasyProTech LLC"
__license__ = "MIT"
__copyright__ = "Copyright (c) 2025 EasyProTech LLC"

__all__ = [
    "EXTENDED_DB_VERSION",
    "KB_BUILD",
    "KB_REVISION",
    "KB_VERSION",
    "PAYLOAD_DB_VERSION",
    "REVERSE_MAP_VERSION",
    "VERSION",
    "__author__",
    "__build__",
    "__copyright__",
    "__license__",
    "__revision__",
    "__version__",
]
