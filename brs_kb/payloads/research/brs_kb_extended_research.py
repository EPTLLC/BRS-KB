#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Final Frontier XSS Payloads

The absolute last bits of XSS knowledge - extremely specialized vectors,
edge-of-browser-spec exploits, and techniques from the deepest corners.

Refactored into 3 parts for better maintainability.
"""

from .brs_kb_extended_research_part1 import BRS_KB_FINAL_FRONTIER_PAYLOADS_PART1
from .brs_kb_extended_research_part2 import BRS_KB_FINAL_FRONTIER_PAYLOADS_PART2
from .brs_kb_extended_research_part3 import BRS_KB_FINAL_FRONTIER_PAYLOADS_PART3


BRS_KB_FINAL_FRONTIER_PAYLOADS = {
    **BRS_KB_FINAL_FRONTIER_PAYLOADS_PART1,
    **BRS_KB_FINAL_FRONTIER_PAYLOADS_PART2,
    **BRS_KB_FINAL_FRONTIER_PAYLOADS_PART3,
}

BRS_KB_FINAL_FRONTIER_TOTAL_PAYLOADS = len(BRS_KB_FINAL_FRONTIER_PAYLOADS)
