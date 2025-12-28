#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-27 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Next.js App Router Context - Data Module
"""

DESCRIPTION = """
Next.js App Router uses React Server Components and new routing.
Vulnerabilities occur when user input is injected into server components,
client components, or route handlers, allowing XSS attacks.

Vulnerability occurs when:
- User-controlled data is injected into server components
- Client components use unsanitized input
- Route handlers return user input
- dangerouslySetInnerHTML uses user input
- Server actions process user input unsafely

Common injection points:
- Server Component props
- Client Component props
- Route handler responses
- dangerouslySetInnerHTML
- Server actions
- Metadata API
"""

ATTACK_VECTOR = """
1. Server Component injection:
   export default function Page({ params }) {
       return <div>{params.userInput}</div>;
   }

2. dangerouslySetInnerHTML:
   <div dangerouslySetInnerHTML={{__html: USER_INPUT}} />

3. Route handler injection:
   export async function GET(request) {
       return new Response(USER_INPUT);
   }

4. Metadata injection:
   export const metadata = {
       title: USER_INPUT
   };

5. Server action injection:
   async function action(formData) {
       const data = formData.get('input');
       return <div>{data}</div>;
   }
"""

REMEDIATION = """
1. Never use dangerouslySetInnerHTML with user input
2. Sanitize all user input before rendering
3. Validate server component props
4. Use Content Security Policy (CSP)
5. Escape HTML entities in user-controlled content
6. Audit all Next.js components for user input
7. Validate route handler responses
8. Use framework-safe methods for rendering
"""
