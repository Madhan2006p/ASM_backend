"""
Faraday vulnerability import helper.

Sends vulnerability data directly to Faraday's API using the credentials
configured in Django settings.  This bypasses the external Faraday pipeline
service and connects to Faraday on port 5985 directly.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

import psycopg2
import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class FaradayImportError(Exception):
    pass


def _authenticate(session: requests.Session) -> None:
    """Authenticate to Faraday API and set the auth token on the session."""
    base = str(getattr(settings, "FARADAY_URL", "http://localhost:5985")).rstrip("/")
    username = str(getattr(settings, "FARADAY_USERNAME", "faraday"))
    password = str(getattr(settings, "FARADAY_PASSWORD", "changeme"))
    verify = bool(getattr(settings, "FARADAY_VERIFY_SSL", False))

    # Try email first, then username
    for login_field in ("email", "username"):
        try:
            resp = session.post(
                f"{base}/_api/login",
                json={login_field: username, "password": password},
                verify=verify,
                timeout=30,
            )
            if resp.status_code == 200:
                payload = resp.json()
                # Faraday v5.2 response format: token is at response.user.authentication_token
                user_data = payload.get("response", {}).get("user", {})
                token = (
                    user_data.get("authentication_token")
                    or payload.get("token")
                    or payload.get("access_token")
                    or payload.get("jwt")
                )
                if token:
                    session.headers.update({"Authorization": f"Bearer {token}"})
                    return
        except requests.RequestException:
            continue

    # Fallback to HTTP Basic Auth
    session.auth = (username, password)

# ── PostgreSQL connection helpers ─────────────────────────────────────────

def _get_faraday_pg_connection():
    """Return a psycopg2 connection to Faraday's PostgreSQL database."""
    return psycopg2.connect(
        host="localhost",
        port=5435,
        dbname="faraday",
        user="faraday",
        password="faraday",
        connect_timeout=5,
    )


def _get_or_create_host(cur, workspace_id: int, subdomain: str, domain: str) -> Optional[int]:
    """
    Find a host by hostname or create one. Returns host_id or None on failure.
    """
    target_hostname = subdomain or domain
    if not target_hostname:
        return None

    # Try to find host by exact hostname
    cur.execute(
        """SELECT h.id FROM host h
           JOIN hostname hn ON hn.host_id = h.id
           WHERE hn.name = %s AND hn.workspace_id = %s
           LIMIT 1""",
        (target_hostname, workspace_id),
    )
    row = cur.fetchone()
    if row:
        return row[0]

    # Create a new host
    try:
        cur.execute(
            """INSERT INTO host (ip, description, os, mac, net_segment, workspace_id,
               owned, impact_accountability, impact_availability,
               impact_confidentiality, impact_integrity)
               VALUES (%s, %s, %s, %s, %s, %s, false, false, false, false, false)
               RETURNING id""",
            ("0.0.0.0", domain or target_hostname, "", "", "", workspace_id),
        )
        host_row = cur.fetchone()
        if host_row:
            host_id = host_row[0]
            cur.execute(
                "INSERT INTO hostname (name, host_id, workspace_id) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (target_hostname, host_id, workspace_id),
            )
            return host_id
        return None
    except Exception as exc:
        logger.warning("Failed to create host in Faraday: %s", exc)
        return None


def _insert_vulnerability(cur, workspace_id: int, host_id: int, vuln: Dict[str, Any], index: int) -> bool:
    """Insert a single vulnerability into Faraday's database. Returns True on success."""
    severity = str(vuln.get("severity") or "info").lower()
    # Map severity to Faraday's enum: info -> informational
    severity_map = {
        "info": "informational",
        "informational": "informational",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    }
    severity = severity_map.get(severity, "informational")
    title = vuln.get("vulnerability_id") or vuln.get("template_id") or f"ASM Vulnerability {index}"
    description = vuln.get("finding") or vuln.get("description") or ""
    cve = vuln.get("cve") or ""
    cwe = vuln.get("cwe") or ""
    target = vuln.get("subdomain") or vuln.get("domain") or ""
    template_id = vuln.get("template_id") or vuln.get("vulnerability_id") or f"asm-{index}"
    source_tool = vuln.get("source_tool") or "ASM"
    external_id = f"asm-{source_tool}-{target}-{template_id}"

    try:
        cur.execute(
            """INSERT INTO vulnerability (
                workspace_id, external_id, name, type, status, data,
                description, resolution, severity, host_id,
                confirmed, impact_accountability, impact_availability,
                impact_confidentiality, impact_integrity,
                disassociated_manually, issuetracker, tool, method,
                parameters, parameter_name, path, query_string,
                request, response, website, code
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s
            )
            ON CONFLICT DO NOTHING""",
            (
                workspace_id,
                external_id,
                f"[{source_tool}] {title}",
                "vulnerability",
                "open",
                json.dumps({
                    "cve": cve or None,
                    "cwe": cwe or None,
                    "source_tool": source_tool,
                    "domain": vuln.get("domain", ""),
                }, default=str),
                description or f"Vulnerability found on {target}",
                "Review the affected endpoint and apply vendor guidance.",
                severity,
                host_id,
                False,  # confirmed
                False,  # impact_accountability
                False,  # impact_availability
                False,  # impact_confidentiality
                False,  # impact_integrity
                False,  # disassociated_manually
                "{}",  # issuetracker
                source_tool,
                "",  # method
                "",  # parameters
                "",  # parameter_name
                target,  # path
                "",  # query_string
                "",  # request
                "",  # response
                target,  # website
                "",  # code
            ),
        )
        return cur.rowcount > 0
    except Exception as exc:
        logger.warning("Failed to insert vulnerability into Faraday: %s", exc)
        return False


def _get_authenticated_session() -> Optional[requests.Session]:
    """Create and return an authenticated Faraday session, or None on failure."""
    session = requests.Session()
    try:
        _authenticate(session)
        return session
    except Exception:
        session.close()
        return None


def fetch_faraday_findings() -> Dict[str, Any]:
    """
    Fetch findings from Faraday's API directly.

    Returns a dict with 'findings' list and a 'connected' flag.
    """
    workspace = str(getattr(settings, "FARADAY_WORKSPACE", "nuclei-asm"))
    verify = bool(getattr(settings, "FARADAY_VERIFY_SSL", False))

    session = _get_authenticated_session()
    if not session:
        return {"findings": [], "connected": False, "error": "Could not connect to Faraday. Ensure Faraday server is running."}

    try:
        base = str(getattr(settings, "FARADAY_URL", "http://localhost:5985")).rstrip("/")
        api_path = f"{base}/_api/v3/ws/{workspace}/vulns"

        # Faraday v3 API returns { "vulnerabilities": [{ "id": ..., "value": { ... } }] }
        raw_vulns = []
        url = api_path
        while url:
            resp = session.get(url, verify=verify, timeout=30)
            if resp.status_code != 200:
                break
            payload = resp.json()
            page_vulns = payload.get("vulnerabilities") or payload.get("results") or []
            if isinstance(payload, list):
                page_vulns = payload
            raw_vulns.extend(page_vulns)
            url = payload.get("next")

        # Normalize findings to match frontend expectations
        normalized = []
        seen_cves = set()       # dedup by CVE
        seen_titles = set()     # dedup by normalized title (strip [source_tool] prefix)

        for item in raw_vulns:
            # Each item may have { "id": ..., "value": { ... } } or be flat
            vuln_data = item.get("value") or item
            vuln_id = item.get("id") or vuln_data.get("id") or vuln_data.get("_id") or 0
            severity = str(vuln_data.get("severity") or "Info").capitalize()
            data_raw = vuln_data.get("data")
            parsed_data = {}
            if isinstance(data_raw, str):
                try:
                    parsed_data = json.loads(data_raw)
                except json.JSONDecodeError:
                    pass
            cve = parsed_data.get("cve") or vuln_data.get("cve") or ""
            cwe = parsed_data.get("cwe") or vuln_data.get("cwe") or ""
            raw_title = vuln_data.get("name") or "Untitled finding"
            # Normalize title: strip [source_tool] prefix, lowercase, strip whitespace
            normalized_title = re.sub(r'^\[[^\]]+\]\s*', '', raw_title).strip().lower()

            # Dedup: skip if same CVE already seen on same endpoint, or same normalized title on same endpoint
            endpoint = vuln_data.get("website") or vuln_data.get("path") or vuln_data.get("target") or ""
            dedup_key = None
            if cve and cve != "-":
                dedup_key = ("cve", cve.lower(), endpoint)
            else:
                dedup_key = ("title", normalized_title, endpoint)

            if dedup_key in seen_cves or dedup_key in seen_titles:
                continue
            if dedup_key[0] == "cve":
                seen_cves.add(dedup_key)
            else:
                seen_titles.add(dedup_key)

            endpoint = vuln_data.get("website") or vuln_data.get("path") or vuln_data.get("target") or ""
            normalized.append({
                "finding_id": 1_000_000_000 + int(vuln_id),
                "title": raw_title,
                "severity": severity,
                "cve": cve if cve != "-" else "",
                "cwe": cwe if cwe != "-" else "",
                "description": vuln_data.get("description") or vuln_data.get("desc") or "",
                "mitigation": vuln_data.get("resolution") or "",
                "endpoint": endpoint,
                "active": str(vuln_data.get("status") or "opened").lower() not in {"closed", "confirmed closed", "false positive"},
                "date_found": vuln_data.get("create_date") or vuln_data.get("created_at") or "",
            })

        return {"findings": normalized, "connected": True}

    except requests.RequestException as exc:
        logger.error("Failed to fetch Faraday findings: %s", exc)
        return {"findings": [], "connected": False, "error": f"Faraday connection failed: {exc}"}
    finally:
        session.close()


def fetch_faraday_summary() -> Dict[str, Any]:
    """
    Fetch summary/counts from Faraday's API directly.
    """
    findings_data = fetch_faraday_findings()
    findings = findings_data.get("findings", [])

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "").capitalize()
        if severity in counts:
            counts[severity] += 1

    total = sum(counts.values())
    # Simple risk score calculation
    score = min(100, counts.get("Critical", 0) * 10 + counts.get("High", 0) * 5 + counts.get("Medium", 0) * 2)

    if score >= 50:
        level = "Critical"
    elif score >= 30:
        level = "High"
    elif score >= 15:
        level = "Medium"
    else:
        level = "Low"

    return {
        "total_findings": total,
        "critical_count": counts["Critical"],
        "high_count": counts["High"],
        "medium_count": counts["Medium"],
        "low_count": counts["Low"],
        "risk_score": score,
        "risk_level": level,
    }


def import_vulnerabilities_to_faraday(asm_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Import vulnerabilities directly into Faraday via PostgreSQL.

    This bypasses the Faraday v3 REST API (which has incompatible payload
    requirements) and inserts vulnerabilities into Faraday's PostgreSQL
    database directly. The Faraday Postgres container runs on port 5435.

    Args:
        asm_vulns: List of vulnerability dicts in ASM format.

    Returns:
        Dict with 'status', 'created' count, and optional 'errors'.
    """
    if not asm_vulns:
        return {"status": "skipped", "created": 0}

    workspace_name = str(getattr(settings, "FARADAY_WORKSPACE", "nuclei-asm"))

    try:
        conn = _get_faraday_pg_connection()
        cur = conn.cursor()
    except Exception as exc:
        logger.error("Failed to connect to Faraday PostgreSQL: %s", exc)
        return {"status": "failed", "created": 0, "errors": [{"error": f"Faraday DB connection failed: {exc}"}]}

    try:
        # Get workspace ID
        cur.execute("SELECT id FROM workspace WHERE name = %s", (workspace_name,))
        row = cur.fetchone()
        if not row:
            return {"status": "failed", "created": 0, "errors": [{"error": f"Workspace '{workspace_name}' not found"}]}
        workspace_id = row[0]

        created = 0
        errors = []

        for index, vuln in enumerate(asm_vulns, start=1):
            try:
                subdomain = vuln.get("subdomain") or ""
                domain = vuln.get("domain") or ""

                # Find or create host
                host_id = _get_or_create_host(cur, workspace_id, subdomain, domain)
                if not host_id:
                    errors.append({"index": index, "error": "Could not find or create host in Faraday"})
                    continue

                # Insert vulnerability
                if _insert_vulnerability(cur, workspace_id, host_id, vuln, index):
                    created += 1
                else:
                    errors.append({"index": index, "error": "Failed to insert vulnerability into Faraday DB"})

            except Exception as exc:
                errors.append({"index": index, "error": str(exc)})

        conn.commit()

        result = {"status": "completed", "created": created}
        if errors:
            result["errors"] = errors
            logger.warning("Faraday import completed with %d errors: %s", len(errors), errors[:3])
        return result

    except Exception as exc:
        conn.rollback()
        logger.error("Faraday import failed: %s", exc)
        return {"status": "failed", "created": 0, "errors": [{"error": str(exc)}]}
    finally:
        try:
            cur.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
