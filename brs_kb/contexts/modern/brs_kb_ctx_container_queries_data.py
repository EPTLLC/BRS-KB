#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Container Queries Context - Data Module
"""

DESCRIPTION = """
Container Queries allow styling elements based on container size.
The feature can be exploited for XSS if user input is injected into
container query conditions or container names, allowing CSS injection.

Vulnerability occurs when:
- User-controlled data is injected into @container rule conditions
- Container names contain user input
- Container query values use user input
- container-type or container-name properties use user input

Common injection points:
- @container rule conditions
- container-name CSS property
- container-type property values
- Container query size conditions
"""

ATTACK_VECTOR = """
1. Container name injection:
   .element {
       container-name: USER_INPUT;
   }

2. Container query injection:
   @container USER_INPUT (min-width: 300px) {
       .element { color: red; }
   }

3. Container type injection:
   .element {
       container-type: USER_INPUT;
   }

4. Query condition injection:
   @container sidebar (USER_INPUT) {
       .element { display: none; }
   }

5. CSS expression:
   @container sidebar (expression(USER_INPUT)) {
       .element { color: red; }
   }
"""

REMEDIATION = """
1. Sanitize all user input before using in CSS
2. Validate container names against allowlist
3. Escape CSS special characters
4. Use Content Security Policy (CSP) with style-src
5. Validate container query conditions
6. Avoid user input in CSS properties
7. Use CSS custom properties safely
8. Audit all container query code for user input
"""
