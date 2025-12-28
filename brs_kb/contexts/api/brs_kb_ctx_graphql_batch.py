#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: GraphQL Batch Query XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via GraphQL Batch Queries",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "graphql", "batch", "api", "query", "apollo", "relay"],
    "description": """
GraphQL batch queries allow multiple operations in a single request. XSS can occur
when batch query responses containing user data are rendered without sanitization.

SEVERITY: HIGH
Batch queries can amplify XSS impact. Multiple payloads can be tested in one request.
Common in Apollo, Relay, and custom GraphQL implementations.
""",
    "attack_vector": """
BATCH QUERY XSS:
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { bio } }"}
]
// If bio contains: <script>alert(1)</script>

ALIASED BATCH:
{
  a: user(id: "1") { name }
  b: user(id: "<script>alert(1)</script>") { name }
}

FRAGMENT INJECTION:
{
  ...userFields
}
fragment userFields on User {
  bio  // Contains XSS
}

BATCH MUTATION:
[
  {"query": "mutation { updateBio(bio: \\"<img src=x onerror=alert(1)>\\") }"},
  {"query": "{ me { bio } }"}
]

SUBSCRIPTION + BATCH:
subscription { newMessage { content } }
// content: <script>alert(1)</script>

DIRECTIVE INJECTION:
{ user @include(if: true) { bio } }
""",
    "remediation": """
DEFENSE:

1. SANITIZE all GraphQL response data before rendering
2. Limit batch query size
3. Validate input types strictly
4. Use GraphQL input validation
5. Implement query complexity limits
6. Set CSP headers

SAFE RENDERING:
// Apollo Client
const { data } = useQuery(GET_USER);
<div>{DOMPurify.sanitize(data.user.bio)}</div>

BATCH LIMITS:
// Apollo Server
const server = new ApolloServer({
  plugins: [
    ApolloServerPluginLandingPageDisabled(),
  ],
  allowBatchedHttpRequests: false, // Disable batching
});

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- GraphQL Security Best Practices
""",
}
