"""
Secrets Scanner - walks a directory tree and flags hardcoded credentials:
cloud provider keys, API tokens, private keys, and generic high-entropy
secret assignments that don't match any known vendor format.

Usage:
    python3 scanner.py /path/to/codebase [--json report.json] [--allowlist allowlist.json]
"""

import os
import sys
import json
import argparse
from datetime import datetime

from rules.patterns import PATTERNS, SKIP_EXTENSIONS, SKIP_DIRS, MAX_FILE_SIZE_BYTES, is_generic_match_placeholder
from rules.entropy import find_high_entropy_secrets

DEFAULT_ALLOWLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowlist", "allowlist.json")


def load_allowlist(path=DEFAULT_ALLOWLIST_PATH):
    default = {"paths": [], "substrings": []}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        default.update({k: v for k, v in data.items() if k in default})
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[WARN] Could not load allowlist from {path}: {e}")
    return default


def is_path_allowlisted(file_path, allowlist):
    normalized = file_path.replace("\\", "/")
    return any(fragment.strip("/") in normalized.split("/") for fragment in allowlist["paths"])


def is_finding_allowlisted(snippet, allowlist):
    return any(sub in snippet for sub in allowlist["substrings"])


def redact(snippet, keep=4):
    """Shows just enough of a match to confirm the finding without
    printing the full secret into logs/terminal/CI output."""
    if len(snippet) <= keep * 2:
        return "*" * len(snippet)
    return snippet[:keep] + "*" * (len(snippet) - keep * 2) + snippet[-keep:]


def should_skip_dir(dirname):
    return dirname in SKIP_DIRS


def should_skip_file(file_path):
    _, ext = os.path.splitext(file_path)
    if ext.lower() in SKIP_EXTENSIONS:
        return True
    try:
        if os.path.getsize(file_path) > MAX_FILE_SIZE_BYTES:
            return True
    except OSError:
        return True
    return False


def scan_file(file_path, allowlist):
    findings = []
    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_num, line in enumerate(lines, start=1):
        for name, pattern, severity in PATTERNS:
            for match in pattern.finditer(line):
                matched_text = match.group(0)
                if is_finding_allowlisted(matched_text, allowlist):
                    continue
                if is_generic_match_placeholder(name, matched_text):
                    continue
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "rule": name,
                    "severity": severity,
                    "match_redacted": redact(matched_text),
                })

        for snippet, entropy in find_high_entropy_secrets(line):
            if is_finding_allowlisted(snippet, allowlist):
                continue
            findings.append({
                "file": file_path,
                "line": line_num,
                "rule": f"High-entropy generic secret (entropy={entropy})",
                "severity": "medium",
                "match_redacted": redact(snippet),
            })

    return findings


def scan_directory(root_dir, allowlist):
    all_findings = []
    files_scanned = 0
    files_skipped = 0

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]

        if is_path_allowlisted(dirpath, allowlist):
            continue

        for filename in filenames:
            file_path = os.path.join(dirpath, filename)

            if should_skip_file(file_path) or is_path_allowlisted(file_path, allowlist):
                files_skipped += 1
                continue

            files_scanned += 1
            all_findings.extend(scan_file(file_path, allowlist))

    return all_findings, files_scanned, files_skipped


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def print_report(findings, files_scanned, files_skipped, root_dir):
    print(f"\nScanned {files_scanned} file(s), skipped {files_skipped}, in: {root_dir}\n")

    if not findings:
        print("No secrets detected.")
        return

    findings_sorted = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"]))

    print(f"{len(findings)} potential secret(s) found:\n")
    for f in findings_sorted:
        rel_path = os.path.relpath(f["file"], root_dir)
        print(f"  [{f['severity'].upper():8}] {rel_path}:{f['line']}")
        print(f"             {f['rule']}")
        print(f"             -> {f['match_redacted']}\n")

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(f"{sev}: {count}" for sev, count in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))
    print(f"Summary — {summary}")


def main():
    parser = argparse.ArgumentParser(description="Scan a directory for hardcoded secrets.")
    parser.add_argument("directory", help="Root directory to scan")
    parser.add_argument("--json", help="Write a JSON report to this path")
    parser.add_argument("--allowlist", default=DEFAULT_ALLOWLIST_PATH, help="Path to allowlist.json")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Directory not found: {args.directory}")
        sys.exit(1)

    allowlist = load_allowlist(args.allowlist)
    findings, files_scanned, files_skipped = scan_directory(args.directory, allowlist)
    print_report(findings, files_scanned, files_skipped, args.directory)

    if args.json:
        report = {
            "scanned_at": datetime.now().isoformat(),
            "root_dir": args.directory,
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "total_findings": len(findings),
            "findings": findings,
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.json}")

    # Exit non-zero on critical/high findings - useful for CI pipelines
    if any(f["severity"] in ("critical", "high") for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
