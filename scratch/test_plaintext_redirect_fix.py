"""Validate the plaintext-HTTP false-positive fix.

Expected results:
  - http://uit.ac.in            -> redirects to https, finding SUPPRESSED
  - http://example.com          -> serves content over plaintext HTTP, finding KEPT
  - http://neverssl.com         -> serves content over plaintext HTTP, finding KEPT
"""
import os
import sys
import django

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from attacksurface.scanner.vulnerability_scanner import (
    redirects_to_https,
    run_python_vuln_scanner,
)
from owasp_scanner.detectors.a02_cryptographic_failures import detect_a02
from owasp_scanner.detectors.base import HTTPClient

FAILED = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    if not cond:
        FAILED.append(name)
    print(f"[{status}] {name} {detail}")


print("=== redirects_to_https() ===")
for url in ["http://uit.ac.in", "http://example.com", "http://neverssl.com"]:
    result = redirects_to_https(url)
    print(f"  {url:30s} -> redirects_to_https={result}")

check("uit.ac.in redirects to https (FP suppressed)",
      redirects_to_https("http://uit.ac.in") is True)
check("example.com does NOT redirect (finding kept)",
      redirects_to_https("http://example.com") is False)

print("\n=== run_python_vuln_scanner (HTTP-PLAINTEXT) ===")
# Simulate a raw http:// URL being scanned (run_wapiti/run_nuclei path)
fp = run_python_vuln_scanner("uit.ac.in", [{"url": "http://uit.ac.in", "headers": {}, "status_code": 0}])
ids_fp = [v["vulnerability_id"] for v in fp]
print("  uit.ac.in findings:", ids_fp)
check("uit.ac.in has NO HTTP-PLAINTEXT", "HTTP-PLAINTEXT" not in ids_fp)

real = run_python_vuln_scanner("example.com", [{"url": "http://example.com", "headers": {}, "status_code": 0}])
ids_real = [v["vulnerability_id"] for v in real]
print("  example.com findings:", ids_real)
check("example.com HAS HTTP-PLAINTEXT", "HTTP-PLAINTEXT" in ids_real)

print("\n=== detect_a02 (A02-PLAINTEXT-HTTP) ===")
with HTTPClient() as http:
    f_fp = detect_a02("uit.ac.in", "uit.ac.in", ["http://uit.ac.in", "https://uit.ac.in"], http)
    ids = [f["vulnerability_id"] for f in f_fp]
    print("  uit.ac.in A02 findings:", ids)
    check("uit.ac.in has NO A02-PLAINTEXT-HTTP", "A02-PLAINTEXT-HTTP" not in ids)

    f_real = detect_a02("example.com", "example.com", ["http://example.com", "https://example.com"], http)
    ids_real = [f["vulnerability_id"] for f in f_real]
    print("  example.com A02 findings:", ids_real)
    check("example.com HAS A02-PLAINTEXT-HTTP", "A02-PLAINTEXT-HTTP" in ids_real)

print()
if FAILED:
    print(f"❌ {len(FAILED)} checks FAILED: {FAILED}")
    sys.exit(1)
print("✅ All checks passed — false positive fixed, genuine findings preserved.")
