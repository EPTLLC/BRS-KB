# ADR-002: In-Memory Payload Database

**Status:** Accepted (with future migration plan)  
**Date:** 2025-10-25  
**Deciders:** Brabus / EasyProTech LLC

## Context

Need fast access to payloads for:
- Real-time payload analysis
- Security scanner integration
- CLI operations
- Web UI queries

Options considered:
1. External database (SQLite/PostgreSQL)
2. In-memory dictionary
3. File-based storage (JSON/YAML)

## Decision

Use in-memory dictionary (`PAYLOAD_DATABASE`) with:
- PayloadEntry dataclass for structure
- PayloadIndex for fast search (O(log n))
- Consider migration to SQLite/PostgreSQL in future

**Rationale:**
- Payloads are relatively static (rarely change)
- Fast access critical for performance
- No external dependencies
- Simple deployment

## Consequences

### Positive
- ✅ O(1) lookup performance
- ✅ No external dependencies
- ✅ Simple deployment (no DB setup)
- ✅ Fast startup time
- ✅ Works offline

### Negative
- ⚠️ Memory usage scales with payload count
- ⚠️ No persistence (reload on restart)
- ⚠️ Limited query capabilities
- ⚠️ Not suitable for very large datasets (>10K payloads)

### Future Migration Path
- SQLite for development/testing
- PostgreSQL for production
- Migration scripts provided
- Backward compatibility maintained

## Implementation

- `PAYLOAD_DATABASE`: Dict[str, PayloadEntry]
- `PayloadIndex`: In-memory indexes for search
- ~200 payloads currently (~2MB memory)

## References

- [ARCHITECTURE.md](../ARCHITECTURE.md#payload-database)


