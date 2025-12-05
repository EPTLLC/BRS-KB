# BRS-KB Architecture Documentation

**Project:** BRS-KB (BRS XSS Knowledge Base)  
**Version:** 2.0.0  
**Date:** 2025-10-25  
**Status:** Production-ready

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Module Structure](#module-structure)
4. [Data Flow](#data-flow)
5. [Key Components](#key-components)
6. [Design Decisions (ADR)](#design-decisions-adr)
7. [Performance Considerations](#performance-considerations)
8. [Security Architecture](#security-architecture)

## Overview

BRS-KB is a community-driven XSS (Cross-Site Scripting) knowledge base designed for security researchers, penetration testers, and security scanners. The system provides:

- **27 XSS vulnerability contexts** with detailed attack vectors and remediation strategies
- **200+ payloads** with metadata (severity, CVSS scores, tags, WAF evasion)
- **Reverse mapping** from payloads to contexts and defenses
- **ML-ready features** for automated analysis
- **CLI interface** for security workflows
- **Web UI** for visual exploration
- **Multi-language support** (EN, RU, ZH, ES)

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      BRS-KB System                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Core API   │  │     CLI      │  │   Web UI     │    │
│  │  (brs_kb)   │  │  (cli.py)    │  │  (React)     │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                  │                  │            │
│         └──────────────────┼──────────────────┘          │
│                            │                              │
│  ┌─────────────────────────┼──────────────────────────┐  │
│  │         Core Services Layer                          │  │
│  ├─────────────────────────┼──────────────────────────┤  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │  │
│  │  │   Contexts   │  │   Payloads   │  │  Reverse │ │  │
│  │  │   Manager    │  │    Index     │  │  Mapping │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────┘ │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │  │
│  │  │ Validation   │  │  Logging     │  │    i18n  │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────┘ │  │
│  └─────────────────────────────────────────────────────┘  │
│                            │                              │
│  ┌─────────────────────────┼──────────────────────────┐  │
│  │         Data Layer                                  │  │
│  ├─────────────────────────┼──────────────────────────┤  │
│  │  ┌──────────────┐  ┌──────────────┐              │  │
│  │  │   Contexts   │  │   Payloads   │              │  │
│  │  │  (Modules)   │  │  (Database)  │              │  │
│  │  └──────────────┘  └──────────────┘              │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Component Interaction

```
User/Scanner
    │
    ├──> CLI (cli.py)
    │       │
    │       ├──> Core API (__init__.py)
    │       │       │
    │       │       ├──> Contexts Manager
    │       │       ├──> Payloads DB
    │       │       └──> Reverse Mapping
    │       │
    │       └──> Validation (validation.py)
    │
    ├──> Web UI (React)
    │       │
    │       └──> Core API (via HTTP/REST)
    │
    └──> Direct API Usage
            │
            └──> Core API (__init__.py)
```

## Module Structure

### Core Modules

#### `brs_kb/__init__.py`
**Purpose:** Main API entry point  
**Responsibilities:**
- Initialize knowledge base
- Load context modules dynamically
- Provide public API functions
- Handle versioning and metadata

**Key Functions:**
- `list_contexts()` - Get all available contexts
- `get_vulnerability_details(context)` - Get context details
- `search_payloads(query)` - Search payload database
- `analyze_payload_context(payload, context)` - Analyze payload

#### `brs_kb/contexts/`
**Purpose:** XSS vulnerability context definitions  
**Structure:**
- Each context has a main module (`*_context.py`) < 300 lines
- Data separated into `*_data.py` (description, remediation)
- Attack vectors in `*_attack_vectors.py`
- Base class: `contexts/base.py` (ContextBase)

**Example:**
```
html_content.py (30 lines)
    ├── html_content_data.py (DESCRIPTION, REMEDIATION)
    └── html_content_attack_vectors.py (ATTACK_VECTOR)
```

#### `brs_kb/payloads_db.py`
**Purpose:** Payload database management  
**Structure:**
- In-memory database (PAYLOAD_DATABASE)
- PayloadEntry dataclass
- Search and retrieval functions

**Key Functions:**
- `search_payloads(query)` - Search with relevance scoring
- `get_payloads_by_context(context)` - Get payloads for context
- `get_database_info()` - Database statistics

#### `brs_kb/payload_index.py`
**Purpose:** Fast payload search indexing  
**Structure:**
- PayloadIndex class
- In-memory indexes (payload, description, tags, contexts)
- Tokenization and scoring

**Key Features:**
- O(log n) search performance
- Automatic index building
- Relevance scoring

#### `brs_kb/reverse_map.py`
**Purpose:** Payload → Context → Defense mapping  
**Structure:**
- Pattern-based context detection
- ML-ready feature extraction
- Defense recommendations

**Key Functions:**
- `find_contexts_for_payload(payload)` - Detect contexts
- `get_defenses_for_context(context)` - Get defenses
- `predict_contexts_ml_ready(payload)` - ML features

**Performance:**
- LRU caching (@lru_cache)
- Pre-compiled regex patterns
- Confidence scoring

#### `brs_kb/validation.py`
**Purpose:** Input validation  
**Functions:**
- `validate_context_name()`
- `validate_payload()`
- `validate_severity()`
- `validate_cvss_score()`
- `validate_tags()`
- `validate_search_query()`
- `validate_limit()`
- `validate_context_details()`

#### `brs_kb/logger.py`
**Purpose:** Structured logging  
**Features:**
- JSON formatting for SIEM integration
- Configurable log levels
- File and console handlers
- Context-aware logging

#### `brs_kb/exceptions.py`
**Purpose:** Custom exception hierarchy  
**Exception Types:**
- `BRSKBError` (base)
- `ContextNotFoundError`
- `InvalidPayloadError`
- `ValidationError`
- `DatabaseError`
- `ConfigurationError`
- `ModuleImportError`

#### `brs_kb/i18n.py`
**Purpose:** Internationalization  
**Features:**
- JSON-based translations
- Language switching
- Fallback to English
- Interpolation support

#### `brs_kb/cli.py`
**Purpose:** Command-line interface  
**Commands:**
- `list-contexts` - List all contexts
- `get-context <name>` - Get context details
- `analyze-payload <payload>` - Analyze payload
- `search-payloads <query>` - Search payloads
- `test-payload <payload> <context>` - Test payload
- `generate-report` - Generate report
- `info` - System information
- `validate` - Validate database
- `export` - Export data
- `language <lang>` - Set language

## Data Flow

### Context Loading Flow

```
Application Start
    │
    ├──> _initialize_knowledge_base()
    │       │
    │       ├──> Scan contexts/ directory
    │       │
    │       ├──> Import each context module
    │       │
    │       ├──> Extract DETAILS dictionary
    │       │
    │       └──> Store in _KNOWLEDGE_BASE
    │
    └──> Ready for queries
```

### Payload Analysis Flow

```
User Payload
    │
    ├──> validate_payload()
    │       │
    │       └──> ValidationError if invalid
    │
    ├──> find_contexts_for_payload()
    │       │
    │       ├──> Check cache (@lru_cache)
    │       │
    │       ├──> Search payload database
    │       │       │
    │       │       └──> If found: return with high confidence
    │       │
    │       ├──> Pattern matching
    │       │       │
    │       │       ├──> analyze_payload_with_patterns()
    │       │       │       │
    │       │       │       └──> Match against CONTEXT_PATTERNS
    │       │       │
    │       │       └──> Calculate confidence scores
    │       │
    │       └──> Return contexts + defenses
    │
    └──> Result: {contexts, confidence, defenses, ...}
```

### Search Flow

```
Search Query
    │
    ├──> validate_search_query()
    │
    ├──> search_payloads()
    │       │
    │       ├──> Get PayloadIndex instance
    │       │
    │       ├──> index.search(query)
    │       │       │
    │       │       ├──> Tokenize query
    │       │       │
    │       │       ├──> Score payloads:
    │       │       │       - Exact match: +2.0
    │       │       │       - Token in payload: +1.0
    │       │       │       - Token in description: +0.8
    │       │       │       - Token in tags: +0.6
    │       │       │       - Token in contexts: +0.4
    │       │       │
    │       │       └──> Sort by score (descending)
    │       │
    │       └──> Return top results
    │
    └──> Results with relevance scores
```

## Key Components

### Context System

**Architecture:**
- Modular design: each context is a separate module
- Data separation: content split into multiple files
- Base class: ContextBase for common functionality
- Dynamic loading: contexts loaded at runtime

**Context Structure:**
```python
DETAILS = {
    "title": str,
    "description": str,
    "attack_vector": str,
    "remediation": str,
    "severity": "low|medium|high|critical",
    "cvss_score": float (0.0-10.0),
    "cvss_vector": str,
    "reliability": str,
    "cwe": List[str],
    "owasp": List[str],
    "tags": List[str]
}
```

### Payload Database

**Structure:**
- In-memory dictionary (PAYLOAD_DATABASE)
- Key: payload ID (hash or unique identifier)
- Value: PayloadEntry dataclass

**PayloadEntry:**
```python
@dataclass
class PayloadEntry:
    payload: str
    description: str
    contexts: List[str]
    severity: str
    cvss_score: float
    tags: List[str]
    waf_evasion: bool
    browser_support: List[str]
```

### Reverse Mapping System

**Pattern Matching:**
- 29+ context patterns (regex-based)
- Pre-compiled patterns for performance
- Confidence scoring (0.0-1.0)
- Pattern priority and specificity

**ML-Ready Features:**
- Payload length
- Special characters count
- Script tag detection
- Event handler detection
- Protocol detection (javascript:, data:, etc.)

### Indexing System

**Index Types:**
- Payload index: word → payload_ids
- Description index: word → payload_ids
- Tag index: tag → payload_ids
- Context index: context → payload_ids
- Severity index: severity → payload_ids
- WAF index: payload_ids with WAF evasion

**Performance:**
- O(log n) search complexity
- In-memory storage
- Automatic rebuilding

## Design Decisions (ADR)

### ADR-001: Modular Context Architecture

**Decision:** Split large context files into smaller modules (< 300 lines)

**Context:**
- Original context files were 400-700 lines
- Hard to maintain and review
- Violated single responsibility principle

**Decision:**
- Main context file: only DETAILS dictionary (< 50 lines)
- Data files: DESCRIPTION and REMEDIATION
- Attack vectors: separate file for ATTACK_VECTOR

**Consequences:**
- ✅ Easier to maintain
- ✅ Better code organization
- ✅ Faster code reviews
- ⚠️ More files to manage
- ⚠️ Slightly more complex imports

### ADR-002: In-Memory Payload Database

**Decision:** Use in-memory dictionary instead of external database

**Context:**
- Need fast access to payloads
- Database setup adds complexity
- Payloads are relatively static

**Decision:**
- Store payloads in PAYLOAD_DATABASE dictionary
- Use PayloadIndex for fast search
- Consider migration to SQLite/PostgreSQL in future

**Consequences:**
- ✅ Fast access (O(1) lookup)
- ✅ No external dependencies
- ✅ Simple deployment
- ⚠️ Memory usage scales with payload count
- ⚠️ No persistence (reload on restart)

### ADR-003: LRU Caching for Reverse Mapping

**Decision:** Use functools.lru_cache for reverse mapping functions

**Context:**
- Reverse mapping involves regex matching
- Same payloads analyzed repeatedly
- Performance critical for scanners

**Decision:**
- Cache find_contexts_for_payload() (maxsize=512)
- Cache analyze_payload_with_patterns() (maxsize=256)
- Cache get_defenses_for_context() (maxsize=128)

**Consequences:**
- ✅ Significant performance improvement
- ✅ Reduced CPU usage
- ⚠️ Memory usage for cache
- ⚠️ Cache invalidation complexity

### ADR-004: Structured JSON Logging

**Decision:** Use JSON formatting for logs

**Context:**
- Need SIEM integration
- Structured logs easier to parse
- Better for log aggregation systems

**Decision:**
- JSONFormatter class
- Configurable (JSON or text format)
- Context-aware logging

**Consequences:**
- ✅ SIEM-friendly format
- ✅ Better log analysis
- ⚠️ Less human-readable by default
- ⚠️ Slightly more overhead

### ADR-005: Custom Exception Hierarchy

**Decision:** Create specific exception types instead of generic Exception

**Context:**
- Better error handling
- More informative error messages
- Easier debugging

**Decision:**
- Base class: BRSKBError
- Specific exceptions for each error type
- Include context and details

**Consequences:**
- ✅ Better error messages
- ✅ Easier error handling
- ✅ More maintainable code
- ⚠️ More exception classes to maintain

### ADR-006: Input Validation Module

**Decision:** Centralize validation logic

**Context:**
- Validation needed in CLI and API
- Duplicate code without centralization
- Security-critical

**Decision:**
- Create validation.py module
- Functions for each validation type
- Raise ValidationError on failure

**Consequences:**
- ✅ DRY principle
- ✅ Consistent validation
- ✅ Easier to test
- ⚠️ Additional module dependency

## Performance Considerations

### Optimization Strategies

1. **Caching**
   - LRU cache for reverse mapping
   - Cache size: 128-512 entries
   - Automatic eviction

2. **Indexing**
   - In-memory indexes for payload search
   - O(log n) search complexity
   - Pre-built indexes

3. **Pre-compilation**
   - Regex patterns compiled at module load
   - Avoid recompilation overhead

4. **Lazy Loading**
   - Contexts loaded on first access
   - Indexes built on first search

### Performance Metrics

- Context loading: < 1.0s for 27 contexts
- Payload analysis: < 0.5s per payload
- Search: < 1.0s for typical queries
- Index build: < 2.0s for 200+ payloads

## Security Architecture

### Input Validation

- All user inputs validated
- Payload length limits
- Context name validation
- Search query sanitization

### Error Handling

- No sensitive information in error messages
- Structured error responses
- Logging without exposing internals

### Data Integrity

- Payload database validation
- Context structure validation
- Cross-reference validation

## Future Architecture Considerations

### Planned Improvements

1. **Database Migration**
   - SQLite for development
   - PostgreSQL for production
   - Migration scripts

2. **API Versioning**
   - Versioned endpoints
   - Backward compatibility
   - Deprecation strategy

3. **Performance Metrics**
   - Prometheus metrics
   - Performance monitoring
   - Alerting

4. **Web UI Refactoring**
   - Zustand for state management
   - Better component structure
   - Improved UX

## References

- [README.md](../README.md) - Project overview
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [CHANGELOG.md](../CHANGELOG.md) - Version history


