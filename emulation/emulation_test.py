#!/usr/bin/env python3
"""
emulation_test.py — Safe Emulation & Validation for SharePoint ToolShell
(CVE-2025-53770 / CVE-2025-53771)

Purpose:
    This script is DEFENSIVE ONLY. It does not contain exploit code.
    It validates that the scan_toolshell_iis.py scanner correctly detects
    attack patterns recorded in a synthetic IIS log, then reports
    detection metrics and MITRE ATT&CK mappings.

Usage:
    python emulation_test.py
    python emulation_test.py --log path/to/synthetic_iis.log
                             --scanner path/to/scan_toolshell_iis.py
"""

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── MITRE ATT&CK mappings ──────────────────────────────────────────────────
ATTACK_MAP = [
    {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "description":    "Malicious POST to /_layouts/15/ToolPane.aspx "
                          "with forged SignOut.aspx Referer bypasses "
                          "authentication (CVE-2025-53770).",
        "ioc_pattern":    "ToolPane auth-bypass POST",
    },
    {
        "technique_id":   "T1505.003",
        "technique_name": "Server Software Component: Web Shell",
        "tactic":         "Persistence",
        "description":    "spinstall0.aspx deployed to LAYOUTS directory "
                          "to maintain durable access and extract MachineKey.",
        "ioc_pattern":    "spinstall0.aspx web-shell access",
    },
    {
        "technique_id":   "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic":         "Execution",
        "description":    "Post-exploitation commands executed via the "
                          "web shell (PowerShell / cmd spawned by w3wp.exe).",
        "ioc_pattern":    "w3wp.exe child process",
    },
    {
        "technique_id":   "T1552.004",
        "technique_name": "Unsecured Credentials: Private Keys",
        "tactic":         "Credential Access",
        "description":    "ASP.NET MachineKey stolen from SharePoint "
                          "configuration to forge ViewState payloads.",
        "ioc_pattern":    "MachineKey / ViewState forgery",
    },
]

# ── Ground truth: what the synthetic log SHOULD produce ───────────────────
#   Each entry maps a line number → expected reason string (substring match)
EXPECTED_ALERTS = {
    6: "ToolPane auth-bypass POST",       # malicious POST (line 6)
    7: "spinstall0.aspx web-shell access", # webshell GET (line 7)
}

# Lines that must NOT trigger an alert
EXPECTED_CLEAN = {5, 8}  # normal GET lines


# ── Scanner loader ─────────────────────────────────────────────────────────
def load_scanner(scanner_path: Path):
    """Dynamically import scan_toolshell_iis.py as a module."""
    spec = importlib.util.spec_from_file_location("scanner", scanner_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Core validation ────────────────────────────────────────────────────────
def run_validation(scanner_mod, log_path: Path) -> dict:
    alerts = scanner_mod.scan_file(log_path)
    detected_lines = {a["line"]: a["reason"] for a in alerts}

    results = []

    # True Positives: expected alerts that were detected
    for line, expected_reason in EXPECTED_ALERTS.items():
        detected = line in detected_lines
        actual_reason = detected_lines.get(line, "—")
        results.append({
            "line":            line,
            "category":        "TP" if detected else "FN",
            "expected_reason": expected_reason,
            "actual_reason":   actual_reason,
            "pass":            detected,
        })

    # True Negatives / False Positives: clean lines
    for line in EXPECTED_CLEAN:
        fp = line in detected_lines
        results.append({
            "line":            line,
            "category":        "FP" if fp else "TN",
            "expected_reason": "—",
            "actual_reason":   detected_lines.get(line, "—"),
            "pass":            not fp,
        })

    tp = sum(1 for r in results if r["category"] == "TP")
    fn = sum(1 for r in results if r["category"] == "FN")
    fp = sum(1 for r in results if r["category"] == "FP")
    tn = sum(1 for r in results if r["category"] == "TN")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    return {
        "results":   results,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": precision,
        "recall":    recall,
        "f1":        f1,
        "all_pass":  all(r["pass"] for r in results),
    }


# ── Report generation ──────────────────────────────────────────────────────
def print_report(metrics: dict, log_path: Path, scanner_path: Path):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    bar = "=" * 65

    print(bar)
    print("  ToolShell Safe Emulation Report")
    print(f"  Generated : {now}")
    print(f"  Log       : {log_path}")
    print(f"  Scanner   : {scanner_path}")
    print(bar)

    # ── Per-line test results ──
    print("\n[1] Per-line Test Results")
    print(f"  {'Line':>4}  {'Category':>8}  {'Pass':>4}  Reason")
    print("  " + "-" * 55)
    for r in sorted(metrics["results"], key=lambda x: x["line"]):
        icon = "✓" if r["pass"] else "✗"
        print(f"  {r['line']:>4}  {r['category']:>8}  {icon:>4}  {r['actual_reason']}")

    # ── Detection metrics ──
    print("\n[2] Detection Metrics")
    print(f"  TP={metrics['tp']}  FN={metrics['fn']}  "
          f"FP={metrics['fp']}  TN={metrics['tn']}")
    print(f"  Precision : {metrics['precision']:.2f}")
    print(f"  Recall    : {metrics['recall']:.2f}")
    print(f"  F1 Score  : {metrics['f1']:.2f}")

    # ── MITRE ATT&CK mapping ──
    print("\n[3] MITRE ATT&CK Mapping")
    print(f"  {'Technique ID':>13}  {'Tactic':>20}  Name")
    print("  " + "-" * 60)
    for t in ATTACK_MAP:
        print(f"  {t['technique_id']:>13}  {t['tactic']:>20}  {t['technique_name']}")
    print()
    for t in ATTACK_MAP:
        print(f"  [{t['technique_id']}] {t['description']}")
        print()

    # ── Overall verdict ──
    print("[4] Overall Verdict")
    if metrics["all_pass"]:
        print("  ✓ ALL TEST CASES PASSED — scanner behaves as expected.")
    else:
        failed = [r for r in metrics["results"] if not r["pass"]]
        print(f"  ✗ {len(failed)} test case(s) FAILED:")
        for r in failed:
            print(f"    Line {r['line']}: expected {r['expected_reason']!r}, "
                  f"got {r['actual_reason']!r}")
    print(bar)


def save_json_report(metrics: dict, log_path: Path, scanner_path: Path,
                     out_path: Path):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report = {
        "generated":      now,
        "log_file":       str(log_path),
        "scanner_file":   str(scanner_path),
        "test_results":   metrics["results"],
        "metrics": {
            "TP": metrics["tp"], "FN": metrics["fn"],
            "FP": metrics["fp"], "TN": metrics["tn"],
            "precision": round(metrics["precision"], 4),
            "recall":    round(metrics["recall"],    4),
            "f1":        round(metrics["f1"],        4),
        },
        "mitre_attack":   ATTACK_MAP,
        "all_pass":       metrics["all_pass"],
    }
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    print(f"\n  JSON report saved -> {out_path}")


# ── Entry point ────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ToolShell safe emulation & detection validation")
    parser.add_argument(
        "--log",
        default="synthetic_iis.log",
        help="Path to synthetic IIS log (default: synthetic_iis.log)")
    parser.add_argument(
        "--scanner",
        default="scan_toolshell_iis.py",
        help="Path to scan_toolshell_iis.py (default: same directory)")
    parser.add_argument(
        "--report",
        default="emulation_report.json",
        help="Output path for JSON report (default: emulation_report.json)")
    args = parser.parse_args()

    log_path     = Path(args.log)
    scanner_path = Path(args.scanner)
    report_path  = Path(args.report)

    # Validate paths
    for p, label in [(log_path, "log"), (scanner_path, "scanner")]:
        if not p.exists():
            print(f"[ERROR] {label} file not found: {p}")
            sys.exit(1)

    scanner_mod = load_scanner(scanner_path)
    metrics     = run_validation(scanner_mod, log_path)
    print_report(metrics, log_path, scanner_path)
    save_json_report(metrics, log_path, scanner_path, report_path)

    sys.exit(0 if metrics["all_pass"] else 1)


if __name__ == "__main__":
    main()
