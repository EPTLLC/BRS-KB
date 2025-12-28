#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Created
Telegram: https://t.me/EasyProTech

BRS-KB Intelligence Layer.
Transforms payload database into decision engine.

This is what separates BRS-KB from payload lists.
"""

from .context_matcher import ContextDetection, ContextMatcher
from .ranker import PayloadRanker, RankingStrategy
from .scoring import PayloadScorer, PriorityScore
from .strategy import PayloadStrategy, ScanMode, ScanStrategy, StrategyEngine


__all__ = [
    "ContextDetection",
    "ContextMatcher",
    "PayloadRanker",
    "PayloadScorer",
    "PayloadStrategy",
    "PriorityScore",
    "RankingStrategy",
    "ScanMode",
    "ScanStrategy",
    "StrategyEngine",
]
