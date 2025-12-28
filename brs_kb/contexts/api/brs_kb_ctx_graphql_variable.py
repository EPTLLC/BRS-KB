#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: GraphQL Variable XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via GraphQL Variables",
    "severity": "high",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "graphql", "variables", "api", "json", "injection"],
    "description": """
GraphQL variables are JSON values passed with queries. XSS can occur when variable
values containing payloads are rendered in the response or error messages.

SEVERITY: HIGH
Variables bypass query-level validation. Error messages often reflect variable values.
Type coercion can lead to unexpected XSS vectors.
""",
    "attack_vector": """
VARIABLE XSS:
query GetUser($id: ID!) {
  user(id: $id) { name }
}
variables: {"id": "<script>alert(1)</script>"}
// Error: User with id "<script>..." not found

STRING VARIABLE:
query Search($term: String!) {
  search(term: $term) { results }
}
variables: {"term": "<img src=x onerror=alert(1)>"}

OBJECT VARIABLE:
mutation Update($input: UserInput!) {
  updateUser(input: $input) { id }
}
variables: {"input": {"bio": "<svg onload=alert(1)>"}}

ARRAY VARIABLE:
query GetUsers($ids: [ID!]!) {
  users(ids: $ids) { name }
}
variables: {"ids": ["1", "<script>alert(1)</script>"]}

DEFAULT VALUE BYPASS:
query ($name: String = "<script>alert(1)</script>") {
  greet(name: $name)
}

ENUM INJECTION:
query ($status: Status!) { items(status: $status) }
// If enum validation is weak
""",
    "remediation": """
DEFENSE:

1. VALIDATE variable types strictly
2. Sanitize variables in resolvers
3. Don't reflect variables in error messages
4. Use custom scalars with validation
5. Implement input coercion safely
6. Set CSP headers

CUSTOM SCALAR:
const SafeString = new GraphQLScalarType({
  name: 'SafeString',
  parseValue(value) {
    return DOMPurify.sanitize(value, { ALLOWED_TAGS: [] });
  },
  parseLiteral(ast) {
    if (ast.kind === Kind.STRING) {
      return DOMPurify.sanitize(ast.value, { ALLOWED_TAGS: [] });
    }
    return null;
  }
});

ERROR HANDLING:
// Don't include user input in errors
throw new UserInputError('Invalid input');  // Generic message

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- GraphQL Security Best Practices
""",
}
