#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

SvelteKit Specific Context - Data Module
"""

DESCRIPTION = """
SvelteKit is a framework for building web applications with Svelte.
Vulnerabilities occur when user input is injected into SvelteKit load functions,
form actions, or components, allowing XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into load function responses
- Form actions process user input unsafely
- Components render unsanitized input
- @html template tag uses user input
- Server-side rendering includes user input

Common injection points:
- Load function responses
- Form action responses
- Component props
- @html template tag
- Server-side rendering
- URL parameters
"""

ATTACK_VECTOR = """
1. Load function injection:
   export async function load({ params }) {
       return { data: params.userInput };
   }

2. @html injection:
   {@html USER_INPUT}

3. Component injection:
   <Component prop={USER_INPUT} />

4. Form action injection:
   export const actions = {
       default: async ({ request }) => {
           const data = await request.formData();
           return { result: data.get('input') };
       }
   };

5. Server-side injection:
   <script context="module">
       export const load = ({ params }) => {
           return { userInput: params.input };
       };
   </script>
"""

REMEDIATION = """
1. Never use @html with user input
2. Sanitize all user input before rendering
3. Validate load and action responses
4. Use Content Security Policy (CSP)
5. Escape HTML entities in user-controlled content
6. Audit all SvelteKit components for user input
7. Validate form data
8. Use framework-safe methods for rendering
"""
