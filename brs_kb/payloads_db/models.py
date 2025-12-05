#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-04 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Payload database models
Defines PayloadEntry dataclass
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class PayloadEntry:
    """Enhanced payload entry with metadata"""

    payload: str
    contexts: List[str]
    severity: str
    cvss_score: float
    description: str
    tags: List[str] = field(default_factory=list)
    bypasses: List[str] = field(default_factory=list)
    encoding: str = "none"
    browser_support: List[str] = field(default_factory=list)
    waf_evasion: bool = False
    tested_on: List[str] = field(default_factory=list)
    reliability: str = "high"
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())


