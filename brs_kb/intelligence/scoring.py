#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Payload Scoring Engine.
Computes priority scores for intelligent payload selection.

Formula: priority = severity_weight * reliability_weight * context_match * surface_bonus
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from ..payloads.models import PayloadEntry, Reliability, Severity


class ContextRelevance(float, Enum):
    """How well payload matches the detected context."""

    EXACT = 1.0  # Payload designed for this exact context
    HIGH = 0.8  # Payload works well in this context
    PARTIAL = 0.5  # Payload may work with modifications
    LOW = 0.2  # Unlikely to work, but worth trying
    NONE = 0.0  # Wrong context entirely


@dataclass
class PriorityScore:
    """
    Computed priority score for a payload.

    Higher score = try this payload first.
    Range: 0.0 to 100.0
    """

    payload_id: str
    score: float
    severity_component: float
    reliability_component: float
    context_component: float
    surface_component: float

    # Breakdown for transparency
    reasoning: str

    def __post_init__(self):
        # Clamp score to valid range
        self.score = max(0.0, min(100.0, self.score))

    def __lt__(self, other: "PriorityScore") -> bool:
        return self.score < other.score

    def __gt__(self, other: "PriorityScore") -> bool:
        return self.score > other.score

    def __repr__(self) -> str:
        return f"PriorityScore({self.payload_id}: {self.score:.1f})"


class PayloadScorer:
    """
    Scores payloads based on multiple factors.

    This is the brain of BRS-KB. Not a list lookup - a decision engine.

    Scoring factors:
    1. Severity (CVSS-based): How dangerous if successful
    2. Reliability: How likely to execute
    3. Context match: How well suited for detected context
    4. Attack surface: Bonus for matching target surface

    Usage:
        scorer = PayloadScorer()
        score = scorer.score(payload, context="html_content", surface="client")
    """

    # Severity weights (CVSS-aligned)
    SEVERITY_WEIGHTS: Dict[Severity, float] = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.8,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.2,
        Severity.INFO: 0.1,
    }

    # Reliability weights
    RELIABILITY_WEIGHTS: Dict[Reliability, float] = {
        Reliability.CERTAIN: 1.0,
        Reliability.HIGH: 0.9,
        Reliability.MEDIUM: 0.6,
        Reliability.LOW: 0.3,
        Reliability.EXPERIMENTAL: 0.1,
    }

    # Attack surface bonuses (when surface matches)
    SURFACE_BONUS: float = 1.2  # 20% boost for matching surface

    # Base score multiplier
    BASE_SCORE: float = 100.0

    def __init__(
        self,
        severity_weight: float = 0.3,
        reliability_weight: float = 0.3,
        context_weight: float = 0.25,
        surface_weight: float = 0.15,
    ):
        """
        Initialize scorer with custom weights.

        Args:
            severity_weight: Weight for severity factor (default 0.3)
            reliability_weight: Weight for reliability factor (default 0.3)
            context_weight: Weight for context match (default 0.25)
            surface_weight: Weight for surface match (default 0.15)

        Weights should sum to 1.0 for normalized scoring.
        """
        self.severity_weight = severity_weight
        self.reliability_weight = reliability_weight
        self.context_weight = context_weight
        self.surface_weight = surface_weight

    def score(
        self,
        payload: PayloadEntry,
        payload_id: str,
        context: Optional[str] = None,
        surface: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> PriorityScore:
        """
        Compute priority score for a payload.

        Args:
            payload: PayloadEntry to score
            payload_id: Unique identifier
            context: Target injection context (e.g., "html_content")
            surface: Target attack surface (e.g., "client")
            profile: Target profile filter (e.g., "spa-react")

        Returns:
            PriorityScore with computed priority and breakdown
        """
        reasoning_parts = []

        # 1. Severity component
        sev_weight = self.SEVERITY_WEIGHTS.get(payload.severity, 0.5)
        severity_component = sev_weight * self.BASE_SCORE * self.severity_weight
        reasoning_parts.append(f"severity={payload.severity.value}({sev_weight})")

        # 2. Reliability component
        rel_weight = self.RELIABILITY_WEIGHTS.get(payload.reliability, 0.5)
        reliability_component = rel_weight * self.BASE_SCORE * self.reliability_weight
        reasoning_parts.append(f"reliability={payload.reliability.value}({rel_weight})")

        # 3. Context match component
        context_relevance = self._compute_context_relevance(payload, context)
        context_component = context_relevance * self.BASE_SCORE * self.context_weight
        reasoning_parts.append(f"context_match={context_relevance}")

        # 4. Attack surface component
        surface_match = self._compute_surface_match(payload, surface)
        surface_component = surface_match * self.BASE_SCORE * self.surface_weight
        reasoning_parts.append(f"surface_match={surface_match}")

        # Apply profile filter penalty
        profile_penalty = 1.0
        if profile and payload.profile and payload.profile != profile:
            profile_penalty = 0.5  # 50% penalty for wrong profile
            reasoning_parts.append(f"profile_mismatch({payload.profile}!={profile})")

        # Final score
        raw_score = (
            severity_component + reliability_component + context_component + surface_component
        ) * profile_penalty

        return PriorityScore(
            payload_id=payload_id,
            score=raw_score,
            severity_component=severity_component,
            reliability_component=reliability_component,
            context_component=context_component,
            surface_component=surface_component,
            reasoning=" | ".join(reasoning_parts),
        )

    def _compute_context_relevance(
        self,
        payload: PayloadEntry,
        context: Optional[str],
    ) -> float:
        """Compute how well payload matches the target context."""
        if not context:
            return 0.5  # No context specified, neutral score

        context_lower = context.lower()

        # Exact match
        if context_lower in payload.contexts:
            return ContextRelevance.EXACT.value

        # Partial match (context is substring or vice versa)
        for pc in payload.contexts:
            if context_lower in pc or pc in context_lower:
                return ContextRelevance.HIGH.value

        # Category match (e.g., "html_attribute" matches "html_content")
        context_category = context_lower.split("_")[0] if "_" in context_lower else context_lower
        for pc in payload.contexts:
            pc_category = pc.split("_")[0] if "_" in pc else pc
            if context_category == pc_category:
                return ContextRelevance.PARTIAL.value

        # No match
        return ContextRelevance.LOW.value

    def _compute_surface_match(
        self,
        payload: PayloadEntry,
        surface: Optional[str],
    ) -> float:
        """Compute attack surface match bonus."""
        if not surface or not payload.attack_surface:
            return 0.5  # No surface specified, neutral score

        if payload.attack_surface.value == surface.lower():
            return self.SURFACE_BONUS

        return 0.3  # Different surface, slight penalty

    def batch_score(
        self,
        payloads: Dict[str, PayloadEntry],
        context: Optional[str] = None,
        surface: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> List[PriorityScore]:
        """
        Score multiple payloads and return sorted by priority.

        Args:
            payloads: Dictionary of payload_id -> PayloadEntry
            context: Target context
            surface: Target surface
            profile: Target profile

        Returns:
            List of PriorityScores sorted by score (highest first)
        """
        scores = [
            self.score(payload, payload_id, context, surface, profile)
            for payload_id, payload in payloads.items()
        ]
        return sorted(scores, reverse=True)
