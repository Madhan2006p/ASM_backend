"""
OWASP Scanner - Multi-Format Report Generator
===============================================
Generates JSON, CSV, HTML, and PDF vulnerability reports.
"""
from __future__ import annotations

import csv
import json
import logging
import tempfile
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger('scanner.reporters')


class ReportGenerator:
    """
    Generates reports in JSON, CSV, HTML, and PDF formats
    from an OWASP scan session or report dict.
    """

    def __init__(self, report_data: Dict[str, Any]):
        self.data = report_data
        self.summary = report_data.get('summary', {})
        self.findings_by_cat = report_data.get('findings_by_category', {})
        self.top_findings = report_data.get('top_findings', [])

    def to_json(self, indent: int = 2) -> str:
        """Export report as formatted JSON string."""
        return json.dumps(self.data, indent=indent, default=str)

    def to_csv(self) -> str:
        """Export findings as CSV string."""
        output = StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'Finding Name', 'OWASP Category', 'Severity', 'CVSS Score',
            'CWE ID', 'CVE IDs', 'In CISA KEV', 'Exploit Available',
            'Affected URL', 'Affected Parameter', 'Remediation', 'Detected By'
        ])

        # Rows
        for cat_code, cat_data in self.findings_by_cat.items():
            findings = cat_data.get('findings', [])
            for f in findings:
                writer.writerow([
                    f.get('name', ''),
                    f.get('owasp_category', cat_code),
                    f.get('severity', ''),
                    f.get('cvss_score', ''),
                    f.get('cwe_id', ''),
                    ','.join(f.get('cve_ids', [])),
                    'Yes' if f.get('in_cisa_kev') else 'No',
                    'Yes' if f.get('exploit_available') else 'No',
                    f.get('affected_url', ''),
                    f.get('affected_param', ''),
                    f.get('remediation', '')[:200],
                    f.get('detected_by', ''),
                ])

        return output.getvalue()

    def to_html(() -> str:
        """Export report as self-contained HTML document."""
        # Simple HTML template for standalone viewing
        summary = self.summary
        sev = summary.get('severity_breakdown', {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OWASP Top 10 Security Scan Report - {summary.get('target', '')}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #0f172a; color: #e2e8f0; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
.card {{ background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
.stat-box {{ background: #0f172a; padding: 15px; border-radius: 6px; text-align: center; }}
.stat-val {{ font-size: 24px; font-weight: bold; margin-top: 5px; }}
.CRITICAL {{ color: #ef4444; }} .HIGH {{ color: #f97316; }} .MEDIUM {{ color: #eab308; }} .LOW {{ color: #3b82f6; }} .INFO {{ color: #94a3b8; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
th {{ background: #0f172a; color: #94a3b8; }}
tr:hover {{ background: #334155; }}
.badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
.badge-CRITICAL {{ background: #7f1d1d; color: #fca5a5; }}
.badge-HIGH {{ background: #7c2d12; color: #fdba74; }}
.badge-MEDIUM {{ background: #713f12; color: #fde047; }}
.badge-LOW {{ background: #1e3a8a; color: #93c5fd; }}
</style>
</head>
<body>
<div class="container">
<h1>OWASP Security Scan Report</h1>
<div class="card">
  <h2>Executive Summary</h2>
  <div class="grid">
    <div class="stat-box"><div>Target</div><div class="stat-val" style="font-size: 16px;">{summary.get('target', '')}</div></div>
    <div class="stat-box"><div>Total Findings</div><div class="stat-val">{summary.get('total_findings', 0)}</div></div>
    <div class="stat-box"><div>Critical</div><div class="stat-val CRITICAL">{sev.get('CRITICAL', 0)}</div></div>
    <div class="stat-box"><div>High</div><div class="stat-val HIGH">{sev.get('HIGH', 0)}</div></div>
    <div class="stat-box"><div>Risk Score</div><div class="stat-val" style="color: #f43f5e;">{summary.get('risk_score', 0)}/100</div></div>
  </div>
</div>

<div class="card">
  <h2>Findings by Vulnerability</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>OWASP Category</th><th>Vulnerability Name</th><th>Affected URL</th><th>CWE</th></tr>
    </thead>
    <tbody>
"""
        for cat_code, cat_data in self.findings_by_cat.items():
            for f in cat_data.get('findings', []):
                sev_cls = f.get('severity', 'INFO')
                html += f"""<tr>
  <td><span class="badge badge-{sev_cls}">{sev_cls}</span></td>
  <td>{f.get('owasp_category', cat_code)}</td>
  <td><strong>{f.get('name', '')}</strong></td>
  <td><code>{f.get('affected_url', '')[:60]}</code></td>
  <td>{f.get('cwe_id', '') or '-'}</td>
</tr>\n"""

        html += """    </tbody>
  </table>
</div>
</div>
</body>
</html>"""
        return html
