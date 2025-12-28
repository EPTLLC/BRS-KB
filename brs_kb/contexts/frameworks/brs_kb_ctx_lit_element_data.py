#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Lit Element Context - Data Module
"""

DESCRIPTION = """
Lit Element provides a base class for building web components.
Vulnerabilities occur when user input is injected into Lit Element templates,
properties, or event handlers, allowing execution of arbitrary JavaScript.

Vulnerability occurs when:
- User-controlled data is injected into Lit templates
- Lit properties contain user input
- Event handlers use unsanitized input
- unsafeHTML is used with user input
- Template expressions evaluate user input

Common injection points:
- Lit template expressions
- unsafeHTML directive
- Property bindings
- Event handler bindings
- render() method content
"""

ATTACK_VECTOR = r"""
1. Template injection:
   render() {
       return html\`<div>${USER_INPUT}</div>\`;
   }

2. unsafeHTML injection:
   render() {
       return html\`<div>${unsafeHTML(USER_INPUT)}</div>\`;
   }

3. Property injection:
   render() {
       return html\`<div .innerHTML="${USER_INPUT}"></div>\`;
   }

4. Event handler injection:
   render() {
       return html\`<div @click="${USER_INPUT}">Click</div>\`;
   }

5. Expression injection:
   render() {
       return html\`<div>${eval(USER_INPUT)}</div>\`;
   }
"""

REMEDIATION = """
1. Never use unsafeHTML with user input
2. Sanitize all user input before using in templates
3. Use html template tag for safe HTML rendering
4. Validate Lit properties
5. Use Content Security Policy (CSP)
6. Escape HTML entities in user-controlled content
7. Audit all Lit Element templates for user input
8. Use framework-safe methods for rendering
"""
