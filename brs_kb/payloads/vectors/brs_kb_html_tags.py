#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored - Aggregator
Telegram: https://t.me/EasyProTech

HTML Tag XSS Payloads - Aggregator
Combines all HTML tag related payloads from sub-modules.
"""

from .brs_kb_html_tags_basic_af import HTML_TAG_PAYLOADS_AF
from .brs_kb_html_tags_basic_gm import HTML_TAG_PAYLOADS_GM
from .brs_kb_html_tags_basic_nw import HTML_TAG_PAYLOADS_NW
from .brs_kb_html_tags_comments_owasp import COMMENT_INJECTION_PAYLOADS
from .brs_kb_html_tags_exotic_part1 import EXOTIC_PAYLOADS_PART1
from .brs_kb_html_tags_exotic_part2 import EXOTIC_PAYLOADS_PART2
from .brs_kb_html_tags_html5 import HTML5_MODERN_API_PAYLOADS
from .brs_kb_html_tags_portswigger_sobky_terjanq import PORT_SWIGGER_SOBKY_TERJANQ_PAYLOADS


HTML_TAG_PAYLOADS = {
    **HTML_TAG_PAYLOADS_AF,
    **HTML_TAG_PAYLOADS_GM,
    **HTML_TAG_PAYLOADS_NW,
}

HTML_TAGS_DATABASE = {
    **HTML_TAG_PAYLOADS,
    **COMMENT_INJECTION_PAYLOADS,
    **PORT_SWIGGER_SOBKY_TERJANQ_PAYLOADS,
    **EXOTIC_PAYLOADS_PART1,
    **EXOTIC_PAYLOADS_PART2,
    **HTML5_MODERN_API_PAYLOADS,
}

HTML_TAGS_TOTAL = len(HTML_TAGS_DATABASE)
