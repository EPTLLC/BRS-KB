#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Qwik Framework Context - Data Module
"""

DESCRIPTION = """
Qwik is a framework for building instant-loading web apps.
Vulnerabilities occur when user input is injected into Qwik components,
server-side rendering, or serialized state, allowing XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into Qwik components
- Server-side rendered content contains user input
- Serialized state includes unsanitized input
- dangerouslySetInnerHTML uses user input
- Qwik props contain user input

Common injection points:
- Qwik component props
- dangerouslySetInnerHTML
- Server-side rendering
- Serialized state
- useSignal values
"""

ATTACK_VECTOR = """
1. Component prop injection:
   <Component prop={USER_INPUT} />

2. dangerouslySetInnerHTML:
   <div dangerouslySetInnerHTML={USER_INPUT} />

3. Template injection:
   <div>{USER_INPUT}</div>

4. Signal injection:
   const signal = useSignal(USER_INPUT);

5. Server-side injection:
   export default component$(({ userInput }) => {
       return <div>{userInput}</div>;
   });
"""

REMEDIATION = """
1. Never use dangerouslySetInnerHTML with user input
2. Sanitize all user input before rendering
3. Validate Qwik component props
4. Use Content Security Policy (CSP)
5. Escape HTML entities in user-controlled content
6. Audit all Qwik components for user input
7. Validate serialized state
8. Use framework-safe methods for rendering
"""
