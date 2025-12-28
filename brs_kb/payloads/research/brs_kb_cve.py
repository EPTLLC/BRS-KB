#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

1-Day XSS Payloads - Known CVEs and Historical Browser Bugs

Real-world exploits that were discovered and patched.
Many still work on unpatched systems or have bypass variants.

Refactored into 3 parts for better maintainability.
"""

from .brs_kb_cve_part1 import BRS_KB_1DAY_CVE_PAYLOADS_PART1
from .brs_kb_cve_part2 import BRS_KB_1DAY_CVE_PAYLOADS_PART2
from .brs_kb_cve_part3 import BRS_KB_1DAY_CVE_PAYLOADS_PART3


BRS_KB_1DAY_CVE_PAYLOADS = {
    **BRS_KB_1DAY_CVE_PAYLOADS_PART1,
    **BRS_KB_1DAY_CVE_PAYLOADS_PART2,
    **BRS_KB_1DAY_CVE_PAYLOADS_PART3,
}

BRS_KB_1DAY_CVE_TOTAL_PAYLOADS = len(BRS_KB_1DAY_CVE_PAYLOADS)
