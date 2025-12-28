#!/usr/bin/env python3
# Project: BRS-KB
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-12-27 UTC
# Status: Refactored
# Telegram: https://t.me/EasyProTech

"""
Next.js XSS Context

XSS vulnerabilities specific to Next.js applications.
"""

DETAILS = {
    "title": "Next.js XSS",
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reliability": "high",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["nextjs", "react", "framework", "xss", "ssr"],
    "description": """
Next.js XSS can occur through SSR data injection, dangerouslySetInnerHTML
usage, API route reflection, and improper handling of getServerSideProps/
getStaticProps data. Image component src injection and router parameter
reflection are also attack vectors.
""",
    "attack_vector": """
NEXT.JS XSS VECTORS:

1. DANGEROUSLYSETINNERHTML
   <div dangerouslySetInnerHTML={{ __html: userData }} />

2. GETSERVERSIDEPROPS
   export async function getServerSideProps({ query }) {
     return { props: { html: query.q } }
   }

3. GETSTATICPROPS PATH
   Injection via dynamic path params

4. API ROUTE REFLECTION
   export default (req, res) => {
     res.send(req.query.q)
   }

5. IMAGE SRC INJECTION
   <Image src={userUrl} />
   With javascript: or data:

6. ROUTER QUERY XSS
   const { q } = useRouter().query

7. HEAD META INJECTION
   <Head><meta content={userData} /></Head>

8. SSR HTML INJECTION
   Server-rendered with user input

9. __NEXT_DATA__ MANIPULATION
   window.__NEXT_DATA__ tampering

10. MIDDLEWARE REDIRECT
    NextResponse.redirect(userUrl)
""",
    "remediation": """
NEXT.JS XSS PREVENTION:

1. AVOID DANGEROUSLYSETINNERHTML
   Use text content: {userData}
   Not: dangerouslySetInnerHTML

2. SANITIZE SSR DATA
   import DOMPurify from 'isomorphic-dompurify'
   return { props: { html: DOMPurify.sanitize(input) } }

3. VALIDATE API INPUTS
   Check and sanitize query/body

4. USE TEXTCONTENT
   ref.current.textContent = input

5. IMPLEMENT CSP
   next.config.js headers
   Use @next/headers

6. VALIDATE URLS
   Check before Image src
   Block javascript: protocol

7. SANITIZE HEAD DATA
   Escape meta content
""",
}
