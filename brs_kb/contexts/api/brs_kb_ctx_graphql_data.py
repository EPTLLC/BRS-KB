#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

GraphQL XSS Context - Data Module
Contains description and remediation data
"""

DESCRIPTION = """
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
"""

REMEDIATION = r"""
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
