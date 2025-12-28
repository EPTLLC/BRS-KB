#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

SolidJS Context - Data Module
"""

DESCRIPTION = """
SolidJS is a reactive JavaScript framework.
Vulnerabilities occur when user input is injected into SolidJS components,
signals, or effects, allowing XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into SolidJS components
- Signals contain unsanitized input
- Effects process user input unsafely
- dangerouslySetInnerHTML uses user input
- JSX expressions evaluate user input

Common injection points:
- SolidJS component props
- dangerouslySetInnerHTML
- Signal values
- Effect functions
- JSX template expressions
"""

ATTACK_VECTOR = """
1. Component prop injection:
   <Component prop={USER_INPUT} />

2. dangerouslySetInnerHTML:
   <div innerHTML={USER_INPUT} />

3. Template injection:
   <div>{USER_INPUT}</div>

4. Signal injection:
   const [value, setValue] = createSignal(USER_INPUT);

5. Effect injection:
   createEffect(() => {
       document.body.innerHTML = USER_INPUT;
   });
"""

REMEDIATION = """
1. Never use innerHTML with user input
2. Sanitize all user input before rendering
3. Validate SolidJS component props
4. Use Content Security Policy (CSP)
5. Escape HTML entities in user-controlled content
6. Audit all SolidJS components for user input
7. Validate signal values
8. Use framework-safe methods for rendering
"""
