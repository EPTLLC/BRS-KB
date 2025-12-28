#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Payload indexing module for fast search
Provides in-memory indexes for efficient payload lookup
"""

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from brs_kb.payloads import PAYLOAD_DATABASE, PayloadEntry


class PayloadIndex:
    """In-memory index for fast payload search"""

    def __init__(self):
        """Initialize payload indexes"""
        self._initialized = False
        self._payload_index: Dict[str, Set[str]] = defaultdict(set)  # word -> payload_ids
        self._description_index: Dict[str, Set[str]] = defaultdict(set)  # word -> payload_ids
        self._tag_index: Dict[str, Set[str]] = defaultdict(set)  # tag -> payload_ids
        self._context_index: Dict[str, Set[str]] = defaultdict(set)  # context -> payload_ids
        self._severity_index: Dict[str, Set[str]] = defaultdict(set)  # severity -> payload_ids
        self._waf_index: Set[str] = set()  # payload_ids with WAF evasion
        self._payload_lowercase: Dict[str, str] = {}  # payload_id -> lowercase payload

    def _tokenize(self, text: str) -> List[str]:
        """
        Tokenize text into searchable words

        Args:
            text: Text to tokenize

        Returns:
            List of tokens
        """
        # Simple tokenization: split by non-alphanumeric characters
        import re

        tokens = re.findall(r"\b\w+\b", text.lower())
        return tokens

    def build_indexes(self) -> None:
        """Build all indexes from payload database"""
        if self._initialized:
            return

        for payload_id, payload in PAYLOAD_DATABASE.items():
            # Index payload content
            payload_tokens = self._tokenize(payload.payload)
            for token in payload_tokens:
                self._payload_index[token].add(payload_id)

            self._payload_lowercase[payload_id] = payload.payload.lower()

            # Index description
            desc_tokens = self._tokenize(payload.description)
            for token in desc_tokens:
                self._description_index[token].add(payload_id)

            # Index tags
            for tag in payload.tags:
                tag_lower = tag.lower()
                self._tag_index[tag_lower].add(payload_id)
                # Also index tag tokens
                tag_tokens = self._tokenize(tag)
                for token in tag_tokens:
                    self._tag_index[token].add(payload_id)

            # Index contexts
            for context in payload.contexts:
                context_lower = context.lower()
                self._context_index[context_lower].add(payload_id)
                # Also index context tokens
                context_tokens = self._tokenize(context)
                for token in context_tokens:
                    self._context_index[token].add(payload_id)

            # Index severity
            self._severity_index[payload.severity.lower()].add(payload_id)

            # Index WAF evasion
            if payload.waf_evasion:
                self._waf_index.add(payload_id)

        self._initialized = True

    def search(self, query: str, limit: int = 100) -> List[Tuple[str, PayloadEntry, float]]:
        """
        Search payloads using indexes

        Args:
            query: Search query
            limit: Maximum results to return

        Returns:
            List of tuples (payload_id, payload, relevance_score)
        """
        if not self._initialized:
            self.build_indexes()

        query_lower = query.lower()
        query_tokens = self._tokenize(query)

        # Score payloads
        payload_scores: Dict[str, float] = defaultdict(float)

        # Exact match in payload (highest score)
        for payload_id, payload_lower in self._payload_lowercase.items():
            if query_lower in payload_lower:
                payload_scores[payload_id] += 2.0

        # Token matches in payload
        for token in query_tokens:
            if token in self._payload_index:
                for payload_id in self._payload_index[token]:
                    payload_scores[payload_id] += 1.0

        # Token matches in description
        for token in query_tokens:
            if token in self._description_index:
                for payload_id in self._description_index[token]:
                    payload_scores[payload_id] += 0.8

        # Tag matches
        for token in query_tokens:
            if token in self._tag_index:
                for payload_id in self._tag_index[token]:
                    payload_scores[payload_id] += 0.6

        # Context matches
        for token in query_tokens:
            if token in self._context_index:
                for payload_id in self._context_index[token]:
                    payload_scores[payload_id] += 0.4

        # Convert to list and sort
        results = []
        for payload_id, score in payload_scores.items():
            if score > 0:
                payload = PAYLOAD_DATABASE[payload_id]
                results.append((payload_id, payload, score))

        # Sort by score (descending)
        results.sort(key=lambda x: x[2], reverse=True)

        return results[:limit]

    def search_by_context(self, context: str) -> List[PayloadEntry]:
        """
        Get all payloads for a specific context using index

        Args:
            context: Context name

        Returns:
            List of payload entries
        """
        if not self._initialized:
            self.build_indexes()

        context_lower = context.lower()
        payload_ids = self._context_index.get(context_lower, set())

        return [PAYLOAD_DATABASE[pid] for pid in payload_ids]

    def search_by_tag(self, tag: str) -> List[PayloadEntry]:
        """
        Get all payloads with specific tag using index

        Args:
            tag: Tag name

        Returns:
            List of payload entries
        """
        if not self._initialized:
            self.build_indexes()

        tag_lower = tag.lower()
        payload_ids = self._tag_index.get(tag_lower, set())

        return [PAYLOAD_DATABASE[pid] for pid in payload_ids]

    def search_by_severity(self, severity: str) -> List[PayloadEntry]:
        """
        Get all payloads with specific severity using index

        Args:
            severity: Severity level

        Returns:
            List of payload entries
        """
        if not self._initialized:
            self.build_indexes()

        severity_lower = severity.lower()
        payload_ids = self._severity_index.get(severity_lower, set())

        return [PAYLOAD_DATABASE[pid] for pid in payload_ids]

    def get_waf_bypass_payloads(self) -> List[PayloadEntry]:
        """
        Get all WAF bypass payloads using index

        Returns:
            List of payload entries
        """
        if not self._initialized:
            self.build_indexes()

        return [PAYLOAD_DATABASE[pid] for pid in self._waf_index]

    def get_index_stats(self) -> Dict[str, int]:
        """
        Get index statistics

        Returns:
            Dictionary with index statistics
        """
        if not self._initialized:
            self.build_indexes()

        return {
            "payload_words": len(self._payload_index),
            "description_words": len(self._description_index),
            "tags": len(self._tag_index),
            "contexts": len(self._context_index),
            "severities": len(self._severity_index),
            "waf_bypass_count": len(self._waf_index),
            "total_payloads": len(PAYLOAD_DATABASE),
        }

    def rebuild_indexes(self) -> None:
        """Rebuild all indexes (useful after database updates)"""
        self._initialized = False
        self._payload_index.clear()
        self._description_index.clear()
        self._tag_index.clear()
        self._context_index.clear()
        self._severity_index.clear()
        self._waf_index.clear()
        self._payload_lowercase.clear()
        self.build_indexes()


# Global index instance
_index_instance: PayloadIndex = None


def get_index() -> PayloadIndex:
    """
    Get global payload index instance

    Returns:
        PayloadIndex instance
    """
    global _index_instance
    if _index_instance is None:
        _index_instance = PayloadIndex()
        _index_instance.build_indexes()
    return _index_instance


def rebuild_index() -> None:
    """Rebuild global payload index"""
    global _index_instance
    if _index_instance is not None:
        _index_instance.rebuild_indexes()
    else:
        _index_instance = PayloadIndex()
        _index_instance.build_indexes()
