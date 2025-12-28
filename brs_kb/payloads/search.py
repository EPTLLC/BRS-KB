#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Payload database search functions
Provides search functionality with relevance scoring
"""

import time
from typing import List, Tuple

from .models import PayloadEntry


def _get_full_database():
    """Get the full payload database (lazy import to avoid circular imports)."""
    from . import FULL_PAYLOAD_DATABASE

    return FULL_PAYLOAD_DATABASE


def search_payloads(query: str) -> List[Tuple[PayloadEntry, float]]:
    """Search payloads by query with relevance scoring."""
    from brs_kb.metrics import record_search_query

    start_time = time.time()
    db = _get_full_database()

    try:
        from brs_kb.payload_index import get_index

        index = get_index()
        indexed_results = index.search(query)

        # Convert to expected format: (PayloadEntry, float)
        results = [(payload, score) for _, payload, score in indexed_results]

        # Record metrics
        duration = time.time() - start_time
        record_search_query(query, duration, len(results))
        return results
    except ImportError:
        # Fallback to linear search if index not available
        results = []
        query_lower = query.lower()

        for _payload_id, payload in db.items():
            relevance_score = 0.0

            # Check payload content
            if query_lower in payload.payload.lower():
                relevance_score += 1.0

            # Check description
            if query_lower in payload.description.lower():
                relevance_score += 0.8

            # Check tags
            if any(query_lower in tag.lower() for tag in payload.tags):
                relevance_score += 0.6

            # Check contexts
            if any(query_lower in context.lower() for context in payload.contexts):
                relevance_score += 0.4

            if relevance_score > 0:
                results.append((payload, relevance_score))

        # Sort by relevance score
        results.sort(key=lambda x: x[1], reverse=True)

        # Record metrics
        duration = time.time() - start_time
        record_search_query(query, duration, len(results))
        return results
