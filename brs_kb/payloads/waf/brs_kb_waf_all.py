#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Complete WAF Bypass Payloads Collection

Comprehensive WAF bypass techniques for all major WAFs.

Refactored into 3 parts for better maintainability.
"""

from .brs_kb_waf_all_part1 import BRS_KB_WAF_COMPLETE_PAYLOADS_PART1
from .brs_kb_waf_all_part2 import BRS_KB_WAF_COMPLETE_PAYLOADS_PART2
from .brs_kb_waf_all_part3 import BRS_KB_WAF_COMPLETE_PAYLOADS_PART3


BRS_KB_WAF_COMPLETE_PAYLOADS = {
    **BRS_KB_WAF_COMPLETE_PAYLOADS_PART1,
    **BRS_KB_WAF_COMPLETE_PAYLOADS_PART2,
    **BRS_KB_WAF_COMPLETE_PAYLOADS_PART3,
}
