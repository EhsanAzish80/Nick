#!/usr/bin/env python3
# MARK: - Nick
# Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
# Licensed under AGPL-3.0. See LICENSE for details.
"""
Quality gate for Nick's bundled YARA rules.

  lint  Compile every rule under Rules/ and require explicit metadata:
        class = "signature" | "behavior", severity = INFO..CRITICAL,
        unique rule names, and source/license for third-party family rules.

  fp    Scan a benign corpus (default: Apple and installed applications) and
        fail if any class="signature" rule matches. Behaviour-rule matches are
        reported per rule so noisy heuristics are visible in review.

Requires yara-python (pip install yara-python==4.5.4), which bundles the same
libyara 4.5.x release Nick vendors.
"""

import argparse
import collections
import json
import os
import re
import sys
import time

try:
    import yara
except ImportError:  # pragma: no cover
    sys.exit("yara-python is required: pip install yara-python==4.5.4")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "Rules")
FP_REPORT = os.path.join(ROOT, "yara-fp-report.json")
SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
CLASSES = {"signature", "behavior"}
MACHO_MAGICS = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
                b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}
DEFAULT_CORPUS = [
    "/System/Applications", "/System/Library/CoreServices", "/usr/bin", "/usr/sbin",
    "/usr/libexec", "/Applications", "/opt/homebrew/Cellar", "/usr/local/Cellar",
]


def rule_files():
    for base, _, names in os.walk(RULES):
        for name in sorted(names):
            if name.endswith((".yar", ".yara")):
                yield os.path.join(base, name)


def compile_rules():
    files = list(rule_files())
    if not files:
        sys.exit("No rule files under Rules/")
    return yara.compile(filepaths={os.path.relpath(f, ROOT): f for f in files}), files


def lint():
    compile_rules()  # the complete set must compile together
    problems, names = [], collections.Counter()
    count = 0
    files = list(rule_files())
    for path in files:
        third_party = os.path.relpath(path, RULES).startswith("families" + os.sep)
        for rule in yara.compile(filepath=path):
            count += 1
            names[rule.identifier] += 1
            meta = dict(rule.meta)
            cls = str(meta.get("class", "")).lower()
            sev = str(meta.get("severity", "")).upper()
            if cls not in CLASSES:
                problems.append(f"{rule.identifier}: class must be one of {sorted(CLASSES)}")
            if sev not in SEVERITIES:
                problems.append(f"{rule.identifier}: severity must be one of {sorted(SEVERITIES)}")
            if third_party:
                for key in ("source", "license", "author"):
                    if not meta.get(key):
                        problems.append(f"{rule.identifier}: third-party rule needs '{key}' meta")
    problems += [f"{n}: duplicate rule name ({c}x)" for n, c in names.items() if c > 1]
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    print(f"Linted {count} rules in {len(files)} files: {len(problems)} problem(s).")
    return 1 if problems else 0


def is_candidate(path, size_limit):
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not os.path.isfile(path) or os.path.islink(path) or st.st_size == 0 or st.st_size > size_limit:
        return False
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head in MACHO_MAGICS or head[:2] == b"#!" or bool(st.st_mode & 0o111)


def fp(roots, max_files, size_limit, write_report, time_limit_seconds):
    rules, _ = compile_rules()
    classes = {r.identifier: str(r.meta.get("class", "")).lower() for r in rules}
    signature_hits, behavior_hits = [], collections.defaultdict(list)
    scanned = 0
    deadline = time.monotonic() + time_limit_seconds if time_limit_seconds else None
    timed_out = False
    limit_reached = False
    for root in roots:
        if not os.path.exists(root):
            continue
        for base, dirs, names in os.walk(root):
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                break
            dirs[:] = [d for d in dirs if d not in (".git",)]
            for name in names:
                if scanned >= max_files:
                    limit_reached = True
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    timed_out = True
                    break
                path = os.path.join(base, name)
                if not is_candidate(path, size_limit):
                    continue
                scanned += 1
                try:
                    matches = rules.match(path, timeout=10, fast=True)
                except yara.Error:
                    continue
                for m in matches:
                    if classes.get(m.rule) == "signature":
                        signature_hits.append((m.rule, path))
                    else:
                        behavior_hits[m.rule].append(path)
            if timed_out or limit_reached:
                break
        if timed_out or limit_reached:
            break
    print(f"Scanned {scanned} benign candidate files.")
    for rule, paths in sorted(behavior_hits.items(), key=lambda kv: -len(kv[1])):
        print(f"  behavior {rule}: {len(paths)} match(es), e.g. {paths[0]}")
    for rule, path in signature_hits:
        print(f"error: signature rule {rule} matched benign file {path}", file=sys.stderr)
    if timed_out:
        print(f"error: false-positive scan exceeded {time_limit_seconds} seconds", file=sys.stderr)
    if write_report:
        with open(FP_REPORT, "w", encoding="utf-8") as fh:
            json.dump({
                "scanned": scanned,
                "timed_out": timed_out,
                "signature": [{"rule": r, "path": p} for r, p in signature_hits],
                "behavior": {r: p for r, p in behavior_hits.items()},
            }, fh, indent=2, sort_keys=True)
    return 1 if signature_hits or timed_out else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("lint")
    fpp = sub.add_parser("fp")
    fpp.add_argument("--root", action="append", help="benign corpus root (repeatable)")
    fpp.add_argument("--max-files", type=int, default=250_000)
    fpp.add_argument("--size-limit-mb", type=int, default=100)
    fpp.add_argument("--time-limit-seconds", type=int, default=0,
                     help="fail after this many seconds (0 disables the limit)")
    fpp.add_argument("--report", action="store_true",
                     help="write yara-fp-report.json in the repository root")
    args = parser.parse_args()
    if args.command == "lint":
        return lint()
    return fp(args.root or DEFAULT_CORPUS, args.max_files, args.size_limit_mb * 1024 * 1024,
              args.report, args.time_limit_seconds)


if __name__ == "__main__":
    sys.exit(main())
