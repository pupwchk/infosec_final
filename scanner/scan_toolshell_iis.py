#!/usr/bin/env python3
"""
Defensive IIS log scanner for SharePoint ToolShell-like indicators
(CVE-2025-53770 / CVE-2025-53771).

This tool is DEFENSIVE ONLY. It does not contain or generate any exploit
or proof-of-concept code. It reads existing W3C-format IIS logs and flags
request patterns consistent with publicly reported ToolShell exploitation.

Usage:
    python scan_toolshell_iis.py /path/to/u_ex*.log
    python scan_toolshell_iis.py ../samples/synthetic_iis.log
"""
import glob
import sys
from pathlib import Path

SUSPICIOUS_STEM = "/_layouts/15/toolpane.aspx"
SUSPICIOUS_QUERY = "displaymode=edit&a=/toolpane.aspx"
SUSPICIOUS_REFERER = "/_layouts/signout.aspx"
SUSPICIOUS_WEBSHELL = "/_layouts/15/spinstall0.aspx"


def parse_w3c_line(line, fields):
    """Map a single W3C log line onto the field names from the header."""
    parts = line.rstrip("\n").split()
    if len(parts) < len(fields):
        return None
    return dict(zip(fields, parts))


def scan_file(path):
    fields = []
    alerts = []
    with open(path, "r", encoding="utf-8", errors="ignore") as log:
        for line_number, line in enumerate(log, start=1):
            if line.startswith("#Fields:"):
                fields = line.strip().split()[1:]
                continue
            if not fields or line.startswith("#") or not line.strip():
                continue
            event = parse_w3c_line(line, fields)
            if not event:
                continue

            method = event.get("cs-method", "").upper()
            stem = event.get("cs-uri-stem", "").lower()
            query = event.get("cs-uri-query", "").lower()
            referer = (
                event.get("cs(Referer)", "")
                or event.get("cs-referer", "")
            ).lower()
            source_ip = event.get("c-ip", "unknown")

            suspicious_post = (
                method == "POST"
                and SUSPICIOUS_STEM in stem
                and SUSPICIOUS_QUERY in query
                and SUSPICIOUS_REFERER in referer
            )
            suspicious_webshell = (
                method in {"GET", "POST"}
                and SUSPICIOUS_WEBSHELL in stem
            )

            if suspicious_post or suspicious_webshell:
                alerts.append({
                    "file": str(path),
                    "line": line_number,
                    "source_ip": source_ip,
                    "method": method,
                    "stem": stem,
                    "reason": ("ToolPane auth-bypass POST"
                               if suspicious_post
                               else "spinstall0.aspx web-shell access"),
                })
    return alerts


def main(patterns):
    all_alerts = []
    for pattern in patterns:
        for file_name in glob.glob(pattern):
            path = Path(file_name)
            if path.is_file():
                all_alerts.extend(scan_file(path))

    if not all_alerts:
        print("[OK] No ToolShell-like indicators found.")
        return 0

    print(f"[ALERT] {len(all_alerts)} suspicious event(s) found.")
    for a in all_alerts:
        print(
            f"{a['file']}:{a['line']} "
            f"src={a['source_ip']} method={a['method']} "
            f"uri={a['stem']} reason={a['reason']}"
        )
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan_toolshell_iis.py /path/to/u_ex*.log")
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
