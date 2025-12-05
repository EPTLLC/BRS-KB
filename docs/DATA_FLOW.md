# BRS-KB Data Flow Documentation

**Project:** BRS-KB (BRS XSS Knowledge Base)  
**Version:** 2.0.0  
**Date:** 2025-10-25

## Overview

This document describes the data flow through the BRS-KB system, including how data is loaded, processed, and accessed.

## Data Flow Diagrams

### 1. System Initialization Flow

```
┌─────────────────────────────────────────────────────────┐
│              Application Startup                        │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Import brs_kb module │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  _initialize_kb()      │
         │  (lazy initialization) │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Scan contexts/ dir    │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  For each .py file:   │
         │  - Import module      │
         │  - Extract DETAILS    │
         │  - Store in dict      │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Load PayloadIndex    │
         │  - Build indexes      │
         │  - Tokenize payloads  │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  System Ready          │
         └───────────────────────┘
```

### 2. Payload Analysis Flow

```
┌─────────────────────────────────────────────────────────┐
│              User Provides Payload                      │
│         "<script>alert(1)</script>"                     │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  validate_payload()   │
         │  - Check type         │
         │  - Check length       │
         │  - Sanitize           │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Check LRU Cache       │
         │  - Cache hit?          │
         └───────────┬─────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    Cache Hit                Cache Miss
         │                       │
         │                       ▼
         │          ┌───────────────────────┐
         │          │  Search Payload DB    │
         │          │  - Exact match?       │
         │          └───────────┬─────────────┘
         │                      │
         │          ┌───────────┴───────────┐
         │          │                       │
         │      Found                    Not Found
         │          │                       │
         │          │                       ▼
         │          │          ┌───────────────────────┐
         │          │          │  Pattern Matching     │
         │          │          │  - analyze_patterns() │
         │          │          │  - Score matches      │
         │          │          └───────────┬─────────────┘
         │          │                      │
         │          │                      ▼
         │          │          ┌───────────────────────┐
         │          │          │  Extract Contexts     │
         │          │          │  - Top 3 matches     │
         │          │          │  - Merge contexts     │
         │          │          └───────────┬─────────────┘
         │          │                      │
         │          └──────────────────────┘
         │                      │
         └──────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Get Defenses          │
         │  - For each context    │
         │  - Merge defenses      │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Calculate Confidence  │
         │  - Pattern scores      │
         │  - Match quality       │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Store in Cache        │
         │  (for future use)      │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Return Result         │
         │  {                     │
         │    contexts: [...],     │
         │    confidence: 0.95,    │
         │    defenses: [...],     │
         │    ...                 │
         │  }                     │
         └───────────────────────┘
```

### 3. Payload Search Flow

```
┌─────────────────────────────────────────────────────────┐
│              User Search Query                          │
│         "script alert"                                  │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  validate_search_query()│
         │  - Check length         │
         │  - Sanitize             │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Get PayloadIndex      │
         │  - Build if needed     │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Tokenize Query        │
         │  - Split words         │
         │  - Lowercase           │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Score Payloads        │
         │  ┌─────────────────┐   │
         │  │ Exact match: +2 │   │
         │  │ Payload token: +1│   │
         │  │ Desc token: +0.8│   │
         │  │ Tag token: +0.6 │   │
         │  │ Context: +0.4   │   │
         │  └─────────────────┘   │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Sort by Score         │
         │  (descending)          │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Apply Limit           │
         │  (default: 10)         │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Return Results        │
         │  [                    │
         │    (payload, score),  │
         │    ...                │
         │  ]                    │
         └───────────────────────┘
```

### 4. Context Loading Flow

```
┌─────────────────────────────────────────────────────────┐
│              Request Context Details                     │
│         "html_content"                                  │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  validate_context_name()│
         │  - Check format         │
         │  - Normalize            │
         └───────────┬─────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Check _KNOWLEDGE_BASE │
         │  (in-memory cache)     │
         └───────────┬─────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
      Found                  Not Found
         │                       │
         │                       ▼
         │          ┌───────────────────────┐
         │          │  Try to Import        │
         │          │  - Load module        │
         │          │  - Extract DETAILS    │
         │          └───────────┬─────────────┘
         │                      │
         │          ┌───────────┴───────────┐
         │          │                       │
         │      Success                 Failure
         │          │                       │
         │          │                       ▼
         │          │          ┌───────────────────────┐
         │          │          │  Return Default       │
         │          │          │  Context               │
         │          │          └───────────┬─────────────┘
         │          │                      │
         │          └──────────────────────┘
         │                      │
         └──────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Return Context        │
         │  {                     │
         │    title: "...",       │
         │    description: "...",  │
         │    attack_vector: "...",│
         │    remediation: "...",  │
         │    severity: "...",    │
         │    ...                 │
         │  }                     │
         └───────────────────────┘
```

### 5. Index Building Flow

```
┌─────────────────────────────────────────────────────────┐
│              Index Build Request                        │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Check if initialized  │
         └───────────┬─────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    Already Built          Not Built
         │                       │
         │                       ▼
         │          ┌───────────────────────┐
         │          │  Iterate Payloads     │
         │          │  (PAYLOAD_DATABASE)   │
         │          └───────────┬─────────────┘
         │                      │
         │                      ▼
         │          ┌───────────────────────┐
         │          │  For Each Payload:    │
         │          │  ┌─────────────────┐ │
         │          │  │ Tokenize payload │ │
         │          │  │ Add to index    │ │
         │          │  └─────────────────┘ │
         │          │  ┌─────────────────┐ │
         │          │  │ Index tags      │ │
         │          │  └─────────────────┘ │
         │          │  ┌─────────────────┐ │
         │          │  │ Index contexts  │ │
         │          │  └─────────────────┘ │
         │          │  ┌─────────────────┐ │
         │          │  │ Index severity  │ │
         │          │  └─────────────────┘ │
         │          └───────────┬─────────────┘
         │                      │
         │                      ▼
         │          ┌───────────────────────┐
         │          │  Mark as initialized   │
         │          └───────────┬─────────────┘
         │                      │
         └──────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  Index Ready          │
         └───────────────────────┘
```

## Data Structures

### PayloadEntry Flow

```
PayloadEntry (dataclass)
    │
    ├──> Stored in PAYLOAD_DATABASE
    │       │
    │       └──> Key: payload_id
    │
    ├──> Indexed in PayloadIndex
    │       │
    │       ├──> _payload_index (word → payload_ids)
    │       ├──> _tag_index (tag → payload_ids)
    │       ├──> _context_index (context → payload_ids)
    │       └──> _severity_index (severity → payload_ids)
    │
    └──> Used in search results
            │
            └──> Converted to dict for API
```

### Context Details Flow

```
Context Module (html_content.py)
    │
    ├──> Imports from data files
    │       │
    │       ├──> html_content_data.py
    │       │       ├──> DESCRIPTION
    │       │       └──> REMEDIATION
    │       │
    │       └──> html_content_attack_vectors.py
    │               └──> ATTACK_VECTOR
    │
    ├──> DETAILS dictionary
    │       │
    │       └──> Loaded into _KNOWLEDGE_BASE
    │
    └──> Accessed via get_vulnerability_details()
```

## Performance Optimizations

### Caching Strategy

```
Function Call
    │
    ├──> Check @lru_cache
    │       │
    │       ├──> Cache Hit → Return cached result
    │       │
    │       └──> Cache Miss → Execute function
    │                           │
    │                           └──> Store in cache
```

### Index Usage

```
Search Query
    │
    ├──> Check if index built
    │       │
    │       └──> Build if needed (one-time)
    │
    ├──> Use index for O(log n) lookup
    │       │
    │       └──> Instead of O(n) linear search
    │
    └──> Return results
```

## Error Handling Flow

```
Operation
    │
    ├──> Try execution
    │       │
    │       ├──> Success → Return result
    │       │
    │       └──> Exception
    │               │
    │               ├──> BRSKBError → Handle gracefully
    │               │       │
    │               │       └──> Return error response
    │               │
    │               └──> Other Exception → Log & re-raise
```

## References

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System architecture
- [README.md](../README.md) - Project overview


