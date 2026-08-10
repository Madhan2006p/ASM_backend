"""
OWASP Scanner - Core Data Structures & Base Classes
=====================================================
Shared types, base scanner class, and finding builder used across all detectors.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

import httpx

logger = logging.getLogger(__name__)


# ─── Enumerations ─────────────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "SeverityLevel":
        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class ConfidenceLevel(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"
    CERTAIN = "CERTAIN"


class OWASPCategory(str, Enum):
    A01 = "A01"
    A02 = "A02"
    A03 = "A03"
    A04 = "A04"
    A05 = "A05"
    A06 = "A06"
    A07 = "A07"
    A08 = "A08"
    A09 = "A09"
    A10 = "A10"


OWASP_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ScanTarget:
    """Represents the target being scanned."""
    url: str
    domain: str = ""
    scheme: str = "https"
    port: int = 443
    ip: str = ""
    django_target_id: Optional[int] = None
    session_id: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        parsed = urlparse(self.url)
        self.scheme = parsed.scheme or "https"
        self.domain = parsed.netloc or self.domain
        self.port = parsed.port or (443 if self.scheme == "https" else 80)


@dataclass
class HTTPRequest:
    """Captured HTTP request for evidence."""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    params: Dict[str, str] = field(default_factory=dict)

    def to_raw(self) -> str:
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        lines = [f"{self.method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        if self.body:
            lines.append(f"\n{self.body}")
        return "\n".join(lines)


@dataclass
class HTTPResponse:
    """Captured HTTP response for evidence."""
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0

    def to_raw(self, max_body: int = 2000) -> str:
        lines = [f"HTTP/1.1 {self.status_code}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        body = self.body[:max_body]
        if len(self.body) > max_body:
            body += "\n...[truncated]..."
        lines.append(f"\n{body}")
        return "\n".join(lines)


@dataclass
class Finding:
    """
    A single vulnerability finding. This is the primary output type
    from all detectors. Converted to OWASPFinding model instance before saving.
    """
    name: str
    owasp_category: str              # A01 .. A10
    vulnerability_type: str          # e.g. "SQL Injection"
    severity: SeverityLevel
    confidence: ConfidenceLevel
    affected_url: str

    # Classification
    cwe_id: str = ""
    capec_id: str = ""
    description: str = ""
    risk_description: str = ""
    business_impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # CVE
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_cisa_kev: bool = False
    exploit_available: bool = False
    exploit_references: List[str] = field(default_factory=list)

    # Evidence
    affected_param: str = ""
    affected_header: str = ""
    http_request: Optional[HTTPRequest] = None
    http_response: Optional[HTTPResponse] = None
    evidence: str = ""
    proof: str = ""

    # Meta
    detected_by: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""   # dedup hash

    def __post_init__(self):
        if not self.fingerprint:
            key = f"{self.owasp_category}:{self.vulnerability_type}:{self.affected_url}:{self.affected_param}"
            self.fingerprint = hashlib.md5(key.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "name": self.name,
            "owasp_category": self.owasp_category,
            "owasp_name": OWASP_NAMES.get(self.owasp_category, ""),
            "vulnerability_type": self.vulnerability_type,
            "cwe_id": self.cwe_id,
            "capec_id": self.capec_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cve_ids": self.cve_ids,
            "epss_score": self.epss_score,
            "in_cisa_kev": self.in_cisa_kev,
            "exploit_available": self.exploit_available,
            "affected_url": self.affected_url,
            "affected_param": self.affected_param,
            "affected_header": self.affected_header,
            "evidence": self.evidence,
            "proof": self.proof,
            "description": self.description,
            "risk_description": self.risk_description,
            "business_impact": self.business_impact,
            "remediation": self.remediation,
            "references": self.references,
            "detected_by": self.detected_by,
            "http_request": self.http_request.to_raw() if self.http_request else "",
            "http_response": self.http_response.to_raw() if self.http_response else "",
        }


@dataclass
class AssetInfo:
    """A URL or endpoint discovered during crawl."""
    url: str
    asset_type: str   # URL, API, FORM, PARAM, JS_FILE, DIR, ROBOTS, SITEMAP, AUTH_PAGE
    method: str = "GET"
    params: Dict[str, List[str]] = field(default_factory=dict)
    forms: List[Dict] = field(default_factory=list)
    status_code: int = 0
    content_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)


# ─── HTTP Client Factory ───────────────────────────────────────────────────────

def make_http_client(config: Dict[str, Any]) -> httpx.AsyncClient:
    """Create a shared async HTTP client with scanner settings."""
    http_cfg = config.get("http", {})
    perf_cfg = config.get("performance", {})
    headers = {
        "User-Agent": http_cfg.get("user_agent", "Mozilla/5.0 (compatible; ASM-Scanner/1.0)"),
        **http_cfg.get("default_headers", {}),
    }
    timeout = httpx.Timeout(
        connect=float(perf_cfg.get("connect_timeout", 10)),
        read=float(perf_cfg.get("request_timeout", 30)),
        write=10.0,
        pool=5.0,
    )
    limits = httpx.Limits(
        max_connections=int(perf_cfg.get("max_concurrent_requests", 20)),
        max_keepalive_connections=10,
    )
    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout,
        limits=limits,
        follow_redirects=http_cfg.get("follow_redirects", True),
        max_redirects=int(http_cfg.get("max_redirects", 10)),
        verify=http_cfg.get("verify_ssl", False),
    )


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Simple token-bucket rate limiter for async use."""
    def __init__(self, delay: float = 0.5):
        self.delay = delay
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self.delay - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


# ─── Base Detector ────────────────────────────────────────────────────────────

class BaseDetector:
    """
    Abstract base for all OWASP category detectors.
    Subclasses implement `detect()` which returns a list of Finding objects.
    """
    owasp_category: str = ""
    name: str = ""

    def __init__(
        self,
        target: ScanTarget,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
        config: Dict[str, Any],
        session_logger: Optional[Any] = None,
    ):
        self.target = target
        self.client = client
        self.rate_limiter = rate_limiter
        self.config = config
        self.session_logger = session_logger
        self.log = logging.getLogger(f"scanner.{self.__class__.__name__}")
        self._findings: List[Finding] = []
        self._seen_fingerprints: set = set()

    async def detect(self, assets: List[AssetInfo]) -> List[Finding]:
        """Override in subclass. Returns deduplicated findings."""
        raise NotImplementedError

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Tuple[Optional[httpx.Response], float]:
        """
        Makes an HTTP request with rate limiting & timing.
        Returns (response, elapsed_ms). Returns (None, 0) on error.
        """
        await self.rate_limiter.acquire()
        start = time.monotonic()
        try:
            resp = await self.client.request(method, url, **kwargs)
            elapsed = (time.monotonic() - start) * 1000
            return resp, elapsed
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            self.log.debug("Request error %s %s: %s", method, url, e)
            return None, 0.0

    def _add_finding(self, finding: Finding) -> None:
        if finding.fingerprint not in self._seen_fingerprints:
            self._seen_fingerprints.add(finding.fingerprint)
            self._findings.append(finding)

    def _build_request_obj(
        self, method: str, url: str,
        headers: Optional[Dict] = None,
        body: str = "",
        params: Optional[Dict] = None,
    ) -> HTTPRequest:
        return HTTPRequest(
            method=method, url=url,
            headers=headers or {},
            body=body,
            params=params or {},
        )

    def _build_response_obj(self, resp: httpx.Response, elapsed_ms: float) -> HTTPResponse:
        return HTTPResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text[:4096],
            elapsed_ms=elapsed_ms,
        )

    def _log(self, msg: str, level: str = "INFO"):
        self.log.info(msg)
        if self.session_logger:
            try:
                self.session_logger(level=level, phase=self.name, message=msg)
            except Exception:
                pass


# ─── Finding Builder Helpers ──────────────────────────────────────────────────

class FindingBuilder:
    """Fluent builder for creating Finding objects."""

    def __init__(self):
        self._data: Dict[str, Any] = {
            "severity": SeverityLevel.INFO,
            "confidence": ConfidenceLevel.LOW,
            "references": [],
            "cve_ids": [],
            "exploit_references": [],
            "raw_data": {},
        }

    def name(self, v: str) -> "FindingBuilder":
        self._data["name"] = v; return self

    def category(self, v: str) -> "FindingBuilder":
        self._data["owasp_category"] = v; return self

    def vuln_type(self, v: str) -> "FindingBuilder":
        self._data["vulnerability_type"] = v; return self

    def severity(self, v: SeverityLevel) -> "FindingBuilder":
        self._data["severity"] = v; return self

    def confidence(self, v: ConfidenceLevel) -> "FindingBuilder":
        self._data["confidence"] = v; return self

    def url(self, v: str) -> "FindingBuilder":
        self._data["affected_url"] = v; return self

    def param(self, v: str) -> "FindingBuilder":
        self._data["affected_param"] = v; return self

    def header(self, v: str) -> "FindingBuilder":
        self._data["affected_header"] = v; return self

    def cwe(self, v: str) -> "FindingBuilder":
        self._data["cwe_id"] = v; return self

    def capec(self, v: str) -> "FindingBuilder":
        self._data["capec_id"] = v; return self

    def description(self, v: str) -> "FindingBuilder":
        self._data["description"] = v; return self

    def risk(self, v: str) -> "FindingBuilder":
        self._data["risk_description"] = v; return self

    def impact(self, v: str) -> "FindingBuilder":
        self._data["business_impact"] = v; return self

    def remediation(self, v: str) -> "FindingBuilder":
        self._data["remediation"] = v; return self

    def evidence(self, v: str) -> "FindingBuilder":
        self._data["evidence"] = v; return self

    def proof(self, v: str) -> "FindingBuilder":
        self._data["proof"] = v; return self

    def request(self, v: HTTPRequest) -> "FindingBuilder":
        self._data["http_request"] = v; return self

    def response(self, v: HTTPResponse) -> "FindingBuilder":
        self._data["http_response"] = v; return self

    def add_ref(self, v: str) -> "FindingBuilder":
        self._data["references"].append(v); return self

    def detected_by(self, v: str) -> "FindingBuilder":
        self._data["detected_by"] = v; return self

    def cvss(self, score: float, vector: str = "") -> "FindingBuilder":
        self._data["cvss_score"] = score
        self._data["cvss_vector"] = vector
        return self

    def cves(self, cve_list: List[str]) -> "FindingBuilder":
        self._data["cve_ids"] = cve_list; return self

    def build(self) -> Finding:
        required = ["name", "owasp_category", "vulnerability_type", "affected_url"]
        for r in required:
            if r not in self._data:
                raise ValueError(f"Finding missing required field: {r}")
        return Finding(**self._data)
