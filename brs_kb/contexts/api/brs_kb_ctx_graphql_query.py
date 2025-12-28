#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: GraphQL Query XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via GraphQL Queries",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "graphql", "query", "api", "reflection"],
    "description": """
GraphQL query XSS occurs when query responses containing user data are rendered
without sanitization, or when query syntax is reflected in error messages.

SEVERITY: HIGH
Query responses often contain user-generated content. Error messages may reflect queries.
Introspection can reveal fields that store XSS payloads.
""",
    "attack_vector": """
QUERY RESPONSE XSS:
{
  user(id: 1) {
    bio  // Contains: <script>alert(1)</script>
  }
}

QUERY REFLECTION ERROR:
{ user(id: "<script>alert(1)</script>") }
// Error: Cannot parse id "<script>..."

FIELD ALIAS XSS:
{
  xss: user(id: 1) {
    name
  }
}
// If alias shown in UI

INTROSPECTION ABUSE:
{
  __schema {
    types { name description }
  }
}
// description: <script>alert(1)</script>

DIRECTIVE XSS:
{
  user @deprecated(reason: "<script>alert(1)</script>") { name }
}

FRAGMENT NAME:
query { ...XSS_PAYLOAD }
fragment XSS_PAYLOAD on User { name }

OPERATION NAME:
query <script>alert(1)</script> { user { name } }
""",
    "remediation": """
DEFENSE:

1. SANITIZE all query response data
2. Don't reflect query syntax in errors
3. Validate field names and aliases
4. Limit introspection in production
5. Use parameterized queries
6. Implement CSP

SAFE RENDERING:
const { data } = useQuery(GET_USER);
<div>{data.user.bio}</div>  // Safe if using React/Vue

// If raw HTML needed:
<div dangerouslySetInnerHTML={{
  __html: DOMPurify.sanitize(data.user.bio)
}} />

ERROR HANDLING:
// Don't include query details
throw new GraphQLError('Invalid query');

DISABLE INTROSPECTION:
const server = new ApolloServer({
  introspection: process.env.NODE_ENV !== 'production',
});

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- GraphQL Security
""",
}
