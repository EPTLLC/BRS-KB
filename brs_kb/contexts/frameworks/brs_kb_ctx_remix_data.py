#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Remix Framework Context - Data Module
"""

DESCRIPTION = """
Remix is a full-stack web framework built on React Router.
Vulnerabilities occur when user input is injected into Remix loaders,
actions, or components, allowing XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into loader responses
- Action handlers process user input unsafely
- Components render unsanitized input
- dangerouslySetInnerHTML uses user input
- Form data is rendered without sanitization

Common injection points:
- Loader function responses
- Action function responses
- Component props
- dangerouslySetInnerHTML
- Form submissions
- URL parameters
"""

ATTACK_VECTOR = """
1. Loader injection:
   export async function loader({ params }) {
       return { data: params.userInput };
   }

2. dangerouslySetInnerHTML:
   <div dangerouslySetInnerHTML={{__html: USER_INPUT}} />

3. Component injection:
   export default function Component({ data }) {
       return <div>{data.userInput}</div>;
   }

4. Action injection:
   export async function action({ request }) {
       const formData = await request.formData();
       return { result: formData.get('input') };
   }

5. URL parameter injection:
   <Link to={`/page/${USER_INPUT}`}>Link</Link>
"""

REMEDIATION = """
1. Never use dangerouslySetInnerHTML with user input
2. Sanitize all user input before rendering
3. Validate loader and action responses
4. Use Content Security Policy (CSP)
5. Escape HTML entities in user-controlled content
6. Audit all Remix components for user input
7. Validate form data
8. Use framework-safe methods for rendering
"""
