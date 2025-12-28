#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Astro Framework Context - Data Module
"""

DESCRIPTION = """
Astro is a static site generator with component islands.
Vulnerabilities occur when user input is injected into Astro components,
server-side rendering, or client-side hydration, allowing XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into Astro components
- Server-side rendered content contains user input
- Client-side hydration uses unsanitized input
- Astro props contain user input
- set:html directive uses user input

Common injection points:
- Astro component props
- set:html directive
- Server-side rendering
- Client-side hydration
- Component template expressions
"""

ATTACK_VECTOR = """
1. Component prop injection:
   <Component prop={USER_INPUT} />

2. set:html injection:
   <Fragment set:html={USER_INPUT} />

3. Template injection:
   <div>{USER_INPUT}</div>

4. Server-side injection:
   // In .astro file:
   <div>{Astro.props.userInput}</div>

5. Client-side injection:
   <div client:load>
       <script>document.write(USER_INPUT)</script>
   </div>
"""

REMEDIATION = """
1. Never use set:html with user input
2. Sanitize all user input before using in components
3. Validate Astro props
4. Use Content Security Policy (CSP)
5. Escape HTML entities in user-controlled content
6. Audit all Astro components for user input
7. Use framework-safe methods for rendering
8. Validate server-side rendered content
"""
