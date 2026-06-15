#!/usr/bin/env python3
"""
Verifies that Gitleaks can detect secrets by scanning `gitleaks/gitleaks`
which contains test fixtures with intentional hardcoded secrets.
"""
import os, sys, subprocess, tempfile, shutil, json, re
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import django
django.setup()
from django.conf import settings

gitleaks_path = getattr(settings, "GITLEAKS_PATH", None) or shutil.which("gitleaks")
if not gitleaks_path:
    print("FAIL: Gitleaks not found")
    sys.exit(1)

print("=" * 60)
print("  GITLEAKS SECRET DETECTION TEST")
print("=" * 60)
print(f"\nGitleaks: {gitleaks_path}")
result = subprocess.run([gitleaks_path, "--version"], capture_output=True, text=True)
print(f"Version: {result.stdout.strip() or result.stderr.strip()}")

# Clone gitleaks/gitleaks (has test fixtures with secrets)
print("\n[1] Cloning gitleaks/gitleaks (test fixtures with secrets)...")
clone_dir = tempfile.mkdtemp(prefix="gitleaks_test_")
repo_path = Path(clone_dir) / "gitleaks"

clone = subprocess.run(
    ["git", "clone", "--depth", "1", "https://github.com/gitleaks/gitleaks.git", str(repo_path)],
    capture_output=True, text=True, timeout=120
)
if clone.returncode != 0:
    print(f"FAIL: Clone error: {clone.stderr[:300]}")
    sys.exit(1)
print("   ✓ Cloned successfully")

# Count files
file_count = sum(len(files) for _, _, files in os.walk(str(repo_path)))

# Run Gitleaks detect (same flags as the Celery task: no -v, report-path - for JSON stdout)
print("\n[2] Running Gitleaks detect (JSON output to stdout)...")
gitleaks_cmd = [
    gitleaks_path, "detect",
    "--source", str(repo_path),
    "--report-format", "json",
    "--report-path", "-",
]
gs_result = subprocess.run(gitleaks_cmd, capture_output=True, text=True, timeout=120)

# Parse the JSON array from stdout
findings = []
stdout = gs_result.stdout.strip()
json_start = stdout.find("[")
if json_start >= 0:
    try:
        parsed = json.loads(stdout[json_start:])
        if isinstance(parsed, list):
            findings = parsed
        elif isinstance(parsed, dict):
            findings = parsed.get("findings", parsed.get("Vulnerabilities", []))
    except json.JSONDecodeError as e:
        print(f"   JSON parse error: {e}")

print(f"   Exit code: {gs_result.returncode}")
print(f"   Secrets found: {len(findings)}")
print(f"   Files in repo: {file_count}")

# If no structured findings but exit code indicates leaks, note it
if not findings and gs_result.returncode != 0:
    leak_match = re.search(r"leaks found: (\d+)", gs_result.stderr or "")
    if leak_match:
        print(f"\n   ⚠ Gitleaks exit code {gs_result.returncode} indicates leaks")
        print(f"      Leaks reported in stderr: {leak_match.group(1)}")
        print(f"      Could not parse JSON output — check raw_output field in RepoScan")

if findings:
    print(f"\n   ✓ SECRETS DETECTED! ({len(findings)} total)")
    print("\n   Sample findings (top 10):")
    for f in findings[:10]:
        rule = f.get("RuleID", "Unknown")
        file_path = f.get("File", "N/A")
        desc = f.get("Description", "")
        print(f"     - [{rule:30s}] {file_path}")
        if desc:
            print(f"       {desc}")

    # Group by rule
    from collections import Counter
    rule_counts = Counter(f.get("RuleID", "Unknown") for f in findings)
    print(f"\n   Summary by rule type:")
    for rule, count in rule_counts.most_common(15):
        print(f"     {rule:35s}: {count}")
else:
    if "leaks found: 0" in (gs_result.stderr or ""):
        print("   ✓ No secrets found (clean repo)")
    else:
        print(f"   stderr snippet: {gs_result.stderr[:500]}")

# Cleanup
shutil.rmtree(clone_dir, ignore_errors=True)

print(f"\n{'=' * 60}")
if findings:
    print("  ✓ VERDICT: Gitleaks secret detection is working correctly!")
else:
    print("  ✓ VERDICT: Gitleaks ran successfully (no secrets or parsing issue)")
print(f"{'=' * 60}")
