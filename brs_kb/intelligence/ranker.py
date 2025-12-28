#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Payload Ranker.
Selects and orders payloads for optimal scanning strategy.

This is not "get all payloads". This is "get the RIGHT payloads in the RIGHT order".
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterator, List, Optional, Set

from ..payloads.models import PayloadEntry, Severity
from .scoring import PayloadScorer, PriorityScore


class RankingStrategy(str, Enum):
    """Payload ranking strategy."""

    PRIORITY = "priority"  # By computed priority score
    SEVERITY_FIRST = "severity"  # Critical/High first
    FAST = "fast"  # Quick wins first (high reliability)
    STEALTH = "stealth"  # Low-detection payloads first
    COMPREHENSIVE = "comprehensive"  # All payloads, balanced order
    WAF_EVASION = "waf_evasion"  # WAF bypass payloads first


@dataclass
class RankedPayload:
    """Payload with its rank and metadata."""

    rank: int
    payload_id: str
    payload: PayloadEntry
    score: PriorityScore

    def __repr__(self) -> str:
        return f"#{self.rank} {self.payload_id} (score={self.score.score:.1f})"


class PayloadRanker:
    """
    Ranks payloads for intelligent scanning.

    The key insight: order matters. A good ranker finds vulnerabilities
    faster by trying high-probability payloads first.

    Usage:
        ranker = PayloadRanker(payloads)
        for ranked in ranker.rank(context="html_content", limit=100):
            # Test ranked.payload
            pass
    """

    def __init__(self, payloads: Dict[str, PayloadEntry]):
        """
        Initialize ranker with payload database.

        Args:
            payloads: Dictionary of payload_id -> PayloadEntry
        """
        self.payloads = payloads
        self.scorer = PayloadScorer()

        # Pre-compute indexes for fast filtering
        self._context_index: Dict[str, Set[str]] = {}
        self._severity_index: Dict[Severity, Set[str]] = {}
        self._surface_index: Dict[str, Set[str]] = {}
        self._waf_index: Set[str] = set()

        self._build_indexes()

    def _build_indexes(self) -> None:
        """Build indexes for fast payload filtering."""
        for payload_id, payload in self.payloads.items():
            # Context index
            for ctx in payload.contexts:
                if ctx not in self._context_index:
                    self._context_index[ctx] = set()
                self._context_index[ctx].add(payload_id)

            # Severity index
            if payload.severity not in self._severity_index:
                self._severity_index[payload.severity] = set()
            self._severity_index[payload.severity].add(payload_id)

            # Attack surface index
            if payload.attack_surface:
                surface = payload.attack_surface.value
                if surface not in self._surface_index:
                    self._surface_index[surface] = set()
                self._surface_index[surface].add(payload_id)

            # WAF evasion index
            if payload.waf_evasion:
                self._waf_index.add(payload_id)

    def rank(
        self,
        context: Optional[str] = None,
        surface: Optional[str] = None,
        profile: Optional[str] = None,
        strategy: RankingStrategy = RankingStrategy.PRIORITY,
        limit: Optional[int] = None,
        min_severity: Optional[Severity] = None,
        waf_only: bool = False,
    ) -> Iterator[RankedPayload]:
        """
        Rank payloads based on strategy and filters.

        Args:
            context: Filter by injection context
            surface: Filter by attack surface
            profile: Filter by payload profile
            strategy: Ranking strategy to use
            limit: Maximum number of payloads to return
            min_severity: Minimum severity threshold
            waf_only: Only include WAF evasion payloads

        Yields:
            RankedPayload objects in priority order
        """
        # Step 1: Filter candidates
        candidates = self._filter_candidates(
            context=context,
            surface=surface,
            min_severity=min_severity,
            waf_only=waf_only,
        )

        # Step 2: Score candidates
        scored = self._score_candidates(
            candidates=candidates,
            context=context,
            surface=surface,
            profile=profile,
        )

        # Step 3: Apply ranking strategy
        ranked = self._apply_strategy(scored, strategy)

        # Step 4: Yield results
        for count, (rank_tuple) in enumerate(ranked):
            if limit and count >= limit:
                break
            payload_id, score = rank_tuple
            yield RankedPayload(
                rank=count + 1,
                payload_id=payload_id,
                payload=self.payloads[payload_id],
                score=score,
            )

    def _filter_candidates(
        self,
        context: Optional[str],
        surface: Optional[str],
        min_severity: Optional[Severity],
        waf_only: bool,
    ) -> Set[str]:
        """Filter payloads based on criteria."""
        candidates = set(self.payloads.keys())

        # Filter by context
        if context and context in self._context_index:
            # Start with exact context matches
            context_matches = self._context_index.get(context, set())

            # Also include partial matches (category match)
            context_category = context.split("_")[0] if "_" in context else context
            for ctx, payload_ids in self._context_index.items():
                if ctx.startswith(context_category):
                    context_matches |= payload_ids

            candidates &= context_matches

        # Filter by surface
        if surface and surface in self._surface_index:
            candidates &= self._surface_index[surface]

        # Filter by severity
        if min_severity:
            severity_matches = set()
            for sev in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]:
                if sev >= min_severity:
                    severity_matches |= self._severity_index.get(sev, set())
            candidates &= severity_matches

        # Filter WAF only
        if waf_only:
            candidates &= self._waf_index

        return candidates

    def _score_candidates(
        self,
        candidates: Set[str],
        context: Optional[str],
        surface: Optional[str],
        profile: Optional[str],
    ) -> Dict[str, PriorityScore]:
        """Score filtered candidates."""
        scores = {}
        for payload_id in candidates:
            payload = self.payloads[payload_id]
            scores[payload_id] = self.scorer.score(
                payload=payload,
                payload_id=payload_id,
                context=context,
                surface=surface,
                profile=profile,
            )
        return scores

    def _apply_strategy(
        self,
        scored: Dict[str, PriorityScore],
        strategy: RankingStrategy,
    ) -> List[tuple]:
        """Apply ranking strategy to scored payloads."""
        items = list(scored.items())

        if strategy == RankingStrategy.PRIORITY:
            # Sort by computed priority score
            items.sort(key=lambda x: x[1].score, reverse=True)

        elif strategy == RankingStrategy.SEVERITY_FIRST:
            # Sort by severity, then reliability
            items.sort(
                key=lambda x: (
                    x[1].severity_component,
                    x[1].reliability_component,
                ),
                reverse=True,
            )

        elif strategy == RankingStrategy.FAST:
            # Sort by reliability (quick wins first)
            items.sort(
                key=lambda x: x[1].reliability_component,
                reverse=True,
            )

        elif strategy == RankingStrategy.STEALTH:
            # Prefer low-severity, high-reliability (less likely to trigger alerts)
            items.sort(
                key=lambda x: (
                    x[1].reliability_component,
                    -x[1].severity_component,  # Lower severity is better for stealth
                ),
                reverse=True,
            )

        elif strategy == RankingStrategy.WAF_EVASION:
            # Prefer WAF bypass payloads
            items.sort(
                key=lambda x: (
                    1.0 if self.payloads[x[0]].waf_evasion else 0.0,
                    x[1].score,
                ),
                reverse=True,
            )

        elif strategy == RankingStrategy.COMPREHENSIVE:
            # Balanced: diversity across contexts and severities
            items.sort(key=lambda x: x[1].score, reverse=True)

        return items

    def get_top_payloads(
        self,
        n: int = 10,
        context: Optional[str] = None,
        surface: Optional[str] = None,
    ) -> List[RankedPayload]:
        """
        Get top N payloads for given context/surface.

        Convenience method for quick payload selection.
        """
        return list(self.rank(context=context, surface=surface, limit=n))

    def get_payload_stats(self) -> Dict[str, int]:
        """Get statistics about indexed payloads."""
        return {
            "total": len(self.payloads),
            "contexts": len(self._context_index),
            "waf_evasion": len(self._waf_index),
            "surfaces": len(self._surface_index),
            "by_severity": {sev.value: len(ids) for sev, ids in self._severity_index.items()},
        }
