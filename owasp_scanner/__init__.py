"""
OWASP Top 10 (2021) Vulnerability Scanner
=========================================
Pure-Python scanner that runs detectors for each OWASP Top 10 category
(A01–A10) against a target domain and returns structured findings tagged
with their OWASP category + rank.

Detectors are httpx-based — no external binaries required.
"""

from .engine import run_owasp_top10_scan, OWASP_CATEGORIES

__all__ = ["run_owasp_top10_scan", "OWASP_CATEGORIES"]
