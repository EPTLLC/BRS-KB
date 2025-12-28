#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: Angular Framework XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in Angular Applications",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "angular", "typescript", "bypasssecuritytrust", "ssr", "template"],
    "description": """
Angular has built-in XSS protection via sanitization, but vulnerabilities occur with
bypassSecurityTrust* methods, [innerHTML] binding, and template injection.

SEVERITY: HIGH
Angular's DomSanitizer can be bypassed. Template injection in older versions is critical.
Angular Universal (SSR) introduces additional attack vectors.
""",
    "attack_vector": """
BYPASSSECURITYTRUSTHTML:
this.sanitizer.bypassSecurityTrustHtml(userInput);

INNERHTML BINDING:
<div [innerHTML]="userInput"></div>

TEMPLATE INJECTION (Angular < 1.6):
{{constructor.constructor('alert(1)')()}}

HREF BINDING:
<a [href]="userInput">Link</a>

BYPASSSECURITYTRUSTURL:
this.sanitizer.bypassSecurityTrustUrl('javascript:alert(1)');

STYLE BINDING:
<div [style.backgroundImage]="'url(' + userInput + ')'"></div>

ROUTER NAVIGATE:
this.router.navigate([userInput]);

SRCDOC BINDING:
<iframe [srcdoc]="userInput"></iframe>

DYNAMIC COMPONENT:
const factory = this.resolver.resolveComponentFactory(userComponent);

NG-BIND-HTML (AngularJS):
<div ng-bind-html="userInput"></div>
""",
    "remediation": """
DEFENSE:

1. AVOID bypassSecurityTrust* methods
2. Use Angular's built-in sanitization
3. Validate URLs before binding
4. Don't use user input in templates
5. Implement CSP
6. Keep Angular updated

SAFE PATTERNS:
// Instead of:
<div [innerHTML]="userInput"></div>

// Use:
<div>{{userInput}}</div>  // Auto-escaped

// If HTML needed:
import { DomSanitizer } from '@angular/platform-browser';
// But validate first!

HREF VALIDATION:
isSafeUrl(url: string): boolean {
  return url && !url.toLowerCase().startsWith('javascript:');
}

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- Angular Security Best Practices
""",
}
