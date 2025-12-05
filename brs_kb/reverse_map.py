#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Refactored
Telegram: https://t.me/easyprotech

Advanced Reverse Mapping System: Backward compatibility wrapper
This file maintains backward compatibility while the actual implementation
has been moved to brs_kb/reverse_map/ package
"""

# Import from refactored package for backward compatibility
from brs_kb.reverse_map import (
    ContextPattern,
    CONTEXT_PATTERNS,
    DEFENSE_TO_EFFECTIVENESS,
    CONTEXT_TO_DEFENSES,
    analyze_payload_with_patterns,
    find_contexts_for_payload,
    get_recommended_defenses,
    get_defense_effectiveness,
    get_reverse_map_info,
)

# Export all for backward compatibility
__all__ = [
    "ContextPattern",
    "CONTEXT_PATTERNS",
    "DEFENSE_TO_EFFECTIVENESS",
    "CONTEXT_TO_DEFENSES",
    "analyze_payload_with_patterns",
    "find_contexts_for_payload",
    "get_recommended_defenses",
    "get_defense_effectiveness",
    "get_reverse_map_info",
]
