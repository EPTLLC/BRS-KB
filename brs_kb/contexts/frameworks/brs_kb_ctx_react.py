#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: React Framework XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in React Applications",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "react", "jsx", "dangerouslysetinnerhtml", "ssr", "nextjs"],
    "description": """
React has built-in XSS protection via JSX escaping, but vulnerabilities occur with
dangerouslySetInnerHTML, href attributes, and server-side rendering (SSR).

SEVERITY: HIGH
React apps are not immune to XSS. dangerouslySetInnerHTML bypasses all protections.
SSR introduces additional attack vectors.
""",
    "attack_vector": """
DANGEROUSLYSETINNERHTML:
<div dangerouslySetInnerHTML={{__html: userInput}} />

HREF JAVASCRIPT:
<a href={userInput}>Link</a>
// userInput = "javascript:alert(1)"

SSR HYDRATION:
// Server renders unsanitized HTML, client hydrates it

PROP INJECTION:
<Component {...userControlledProps} />

REF MANIPULATION:
ref.current.innerHTML = userInput;

CSS INJECTION:
<div style={{backgroundImage: `url(${userInput})`}} />

CREATEELEMENT:
React.createElement('div', {dangerouslySetInnerHTML: {__html: payload}});

LINK COMPONENT (NEXT.JS):
<Link href={userInput}>Click</Link>

USEEFFECT INJECTION:
useEffect(() => { document.body.innerHTML = data; }, [data]);

SVG IN JSX:
<svg dangerouslySetInnerHTML={{__html: userInput}} />
""",
    "remediation": """
DEFENSE:

1. AVOID dangerouslySetInnerHTML
2. Sanitize with DOMPurify before dangerouslySetInnerHTML
3. Validate href values - block javascript:
4. Use React's built-in escaping
5. Implement CSP
6. Audit spread operators {...props}

SAFE PATTERNS:
// Instead of:
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Use:
<div>{userInput}</div>  // Auto-escaped

// If HTML needed:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />

HREF VALIDATION:
const isSafeHref = (href) => {
  if (!href) return true;
  return !href.toLowerCase().startsWith('javascript:');
};

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- React Security Best Practices
""",
}
