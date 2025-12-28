#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

View Transitions API XSS Payloads

View Transitions API allows creating smooth transitions between pages.
Can be used for XSS via callback functions and DOM manipulation.

Refactored into 2 parts for better maintainability.
"""

from .brs_kb_view_transitions_part1 import VIEW_TRANSITIONS_API_PAYLOADS_PART1
from .brs_kb_view_transitions_part2 import VIEW_TRANSITIONS_API_PAYLOADS_PART2


VIEW_TRANSITIONS_API_PAYLOADS = {
    **VIEW_TRANSITIONS_API_PAYLOADS_PART1,
    **VIEW_TRANSITIONS_API_PAYLOADS_PART2,
}

VIEW_TRANSITIONS_API_TOTAL_PAYLOADS = len(VIEW_TRANSITIONS_API_PAYLOADS)
