#!/usr/bin/env python3
"""
Nick — Synthetic Training Data Generator
Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
Licensed under AGPL-3.0. See LICENSE for details.

Generates labeled training data for the Nick behavioral threat scoring model.

Produces CSV rows with 40 features + label column matching feature_schema.json.

Usage:
    python3 generate_training_data.py --output training_data.csv --samples 5000
"""

import argparse
import csv
import json
import random
import math
import sys
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "feature_schema.json"
FEATURE_COUNT = 40

# Feature column names in order (must match FeatureVector.featureNames in Swift)
FEATURE_NAMES = [
    "process_is_unsigned",
    "process_is_adhoc_signed",
    "process_in_tmp",
    "process_in_hidden_dir",
    "process_is_shell",
    "process_parent_is_gui_app",
    "process_parent_is_terminal",
    "process_parent_chain_depth",
    "process_age_seconds",
    "process_is_lolbin",
    "net_has_outbound_connection",
    "net_remote_is_raw_ip",
    "net_remote_port",
    "net_remote_port_is_common",
    "net_is_listening",
    "net_connection_count",
    "net_uses_uncommon_port",
    "fs_file_in_tmp",
    "fs_file_entropy",
    "fs_file_entropy_is_high",
    "fs_file_is_macho",
    "fs_file_has_embedded_urls",
    "fs_file_has_embedded_base64",
    "fs_rapid_creation_detected",
    "persist_new_launchagent",
    "persist_new_launchdaemon",
    "persist_new_cronjob",
    "persist_executable_unsigned",
    "persist_executable_missing",
    "yara_match_count",
    "yara_max_severity",
    "audit_sip_disabled",
    "audit_filevault_disabled",
    "audit_gatekeeper_disabled",
    "audit_firewall_disabled",
    "temporal_time_since_file_creation",
    "temporal_time_since_net_connection",
    "temporal_signals_in_window",
    "temporal_unique_monitors_firing",
    "temporal_severity_escalation",
]

assert len(FEATURE_NAMES) == FEATURE_COUNT, f"Expected {FEATURE_COUNT} features, got {len(FEATURE_NAMES)}"


def zero_vec():
    return [0.0] * FEATURE_COUNT


def idx(name: str) -> int:
    return FEATURE_NAMES.index(name)


# ---------------------------------------------------------------------------
# Benign patterns
# ---------------------------------------------------------------------------

def homebrew_install():
    """brew install: shell spawned from Terminal, downloads to temp, signed."""
    v = zero_vec()
    v[idx("process_is_shell")]             = 1
    v[idx("process_parent_is_terminal")]   = 1
    v[idx("process_parent_chain_depth")]   = random.randint(2, 4)
    v[idx("process_age_seconds")]          = random.uniform(5, 300)
    v[idx("net_has_outbound_connection")]  = 1
    v[idx("net_remote_port")]              = 443
    v[idx("net_remote_port_is_common")]    = 1
    v[idx("net_connection_count")]         = random.randint(1, 5)
    v[idx("fs_file_entropy")]              = random.uniform(4.0, 6.5)
    v[idx("temporal_signals_in_window")]   = random.randint(2, 8)
    v[idx("temporal_unique_monitors_firing")] = random.randint(2, 3)
    return v, "benign"


def xcode_build():
    """Xcode build: signed binary in DerivedData, no network, high file I/O."""
    v = zero_vec()
    v[idx("process_parent_is_gui_app")]    = 1
    v[idx("process_parent_chain_depth")]   = random.randint(2, 5)
    v[idx("process_age_seconds")]          = random.uniform(1, 120)
    v[idx("net_connection_count")]         = 0
    v[idx("fs_file_entropy")]              = random.uniform(3.5, 6.0)
    v[idx("temporal_signals_in_window")]   = random.randint(3, 15)
    v[idx("temporal_unique_monitors_firing")] = random.randint(1, 3)
    return v, "benign"


def browser_download():
    """Browser download: signed app, outbound 443, file created."""
    v = zero_vec()
    v[idx("process_parent_is_gui_app")]    = 1
    v[idx("process_age_seconds")]          = random.uniform(60, 3600)
    v[idx("net_has_outbound_connection")]  = 1
    v[idx("net_remote_port")]              = 443
    v[idx("net_remote_port_is_common")]    = 1
    v[idx("net_connection_count")]         = random.randint(1, 10)
    v[idx("fs_file_entropy")]              = random.uniform(5.0, 7.0)
    v[idx("temporal_signals_in_window")]   = random.randint(2, 6)
    v[idx("temporal_unique_monitors_firing")] = 2
    return v, "benign"


def npm_install():
    """npm install: shell from terminal, many files, outbound 443."""
    v = zero_vec()
    v[idx("process_is_shell")]             = 1
    v[idx("process_parent_is_terminal")]   = 1
    v[idx("process_parent_chain_depth")]   = random.randint(2, 3)
    v[idx("process_age_seconds")]          = random.uniform(5, 60)
    v[idx("net_has_outbound_connection")]  = 1
    v[idx("net_remote_port")]              = 443
    v[idx("net_remote_port_is_common")]    = 1
    v[idx("net_connection_count")]         = random.randint(1, 8)
    v[idx("fs_file_entropy")]              = random.uniform(3.5, 5.5)
    v[idx("temporal_signals_in_window")]   = random.randint(5, 20)
    v[idx("temporal_unique_monitors_firing")] = random.randint(2, 4)
    return v, "benign"


BENIGN_PATTERNS = [homebrew_install, xcode_build, browser_download, npm_install]


# ---------------------------------------------------------------------------
# Malicious patterns
# ---------------------------------------------------------------------------

def dropper_execute_c2():
    """Dropper: unsigned binary in /tmp executes and phones home to raw IP."""
    v = zero_vec()
    v[idx("process_is_unsigned")]          = 1
    v[idx("process_in_tmp")]               = 1
    v[idx("process_age_seconds")]          = random.uniform(0, 10)
    v[idx("net_has_outbound_connection")]  = 1
    v[idx("net_remote_is_raw_ip")]         = 1
    v[idx("net_remote_port")]              = random.choice([4444, 1337, 31337, 8080, 9090])
    v[idx("net_uses_uncommon_port")]       = 1
    v[idx("net_connection_count")]         = random.randint(1, 3)
    v[idx("fs_file_in_tmp")]               = 1
    v[idx("fs_file_entropy")]              = random.uniform(7.5, 8.0)
    v[idx("fs_file_entropy_is_high")]      = 1
    v[idx("fs_file_is_macho")]             = 1
    v[idx("yara_match_count")]             = random.randint(1, 3)
    v[idx("yara_max_severity")]            = random.randint(3, 4)
    v[idx("temporal_signals_in_window")]   = random.randint(5, 20)
    v[idx("temporal_unique_monitors_firing")] = random.randint(3, 5)
    v[idx("temporal_severity_escalation")] = 1
    return v, "malicious"


def persistence_unsigned():
    """Persistence installer: writes LaunchAgent pointing to unsigned binary."""
    v = zero_vec()
    v[idx("process_is_unsigned")]          = 1
    v[idx("process_in_tmp")]               = 1
    v[idx("persist_new_launchagent")]      = 1
    v[idx("persist_executable_unsigned")] = 1
    v[idx("fs_file_in_tmp")]               = 1
    v[idx("fs_file_is_macho")]             = 1
    v[idx("yara_match_count")]             = random.randint(0, 2)
    v[idx("yara_max_severity")]            = random.randint(2, 4)
    v[idx("temporal_signals_in_window")]   = random.randint(3, 10)
    v[idx("temporal_unique_monitors_firing")] = random.randint(2, 4)
    v[idx("temporal_severity_escalation")] = random.randint(0, 1)
    return v, "malicious"


def reverse_shell():
    """Reverse shell: shell process with outbound connection to raw IP on high port."""
    v = zero_vec()
    v[idx("process_is_unsigned")]          = 1
    v[idx("process_is_shell")]             = 1
    v[idx("process_in_tmp")]               = random.randint(0, 1)
    v[idx("net_has_outbound_connection")]  = 1
    v[idx("net_remote_is_raw_ip")]         = 1
    v[idx("net_remote_port")]              = random.choice([4444, 1337, 31337, 443, 80])
    v[idx("net_uses_uncommon_port")]       = 1 if v[idx("net_remote_port")] not in (443, 80) else 0
    v[idx("net_connection_count")]         = random.randint(1, 2)
    v[idx("yara_match_count")]             = random.randint(0, 2)
    v[idx("yara_max_severity")]            = random.randint(2, 4)
    v[idx("temporal_signals_in_window")]   = random.randint(3, 12)
    v[idx("temporal_unique_monitors_firing")] = random.randint(2, 4)
    v[idx("temporal_severity_escalation")] = 1
    return v, "malicious"


def data_exfiltration():
    """Data exfil: high-entropy file read, outbound to unusual port, base64 encoded."""
    v = zero_vec()
    v[idx("net_has_outbound_connection")]  = 1
    v[idx("net_remote_is_raw_ip")]         = random.randint(0, 1)
    v[idx("net_remote_port")]              = random.choice([53, 8443, 2222, 9999])
    v[idx("net_uses_uncommon_port")]       = 1
    v[idx("net_connection_count")]         = random.randint(1, 5)
    v[idx("fs_file_entropy")]              = random.uniform(7.0, 8.0)
    v[idx("fs_file_entropy_is_high")]      = 1
    v[idx("fs_file_has_embedded_urls")]    = 1
    v[idx("fs_file_has_embedded_base64")] = 1
    v[idx("temporal_signals_in_window")]   = random.randint(4, 15)
    v[idx("temporal_unique_monitors_firing")] = random.randint(2, 4)
    v[idx("temporal_severity_escalation")] = random.randint(0, 1)
    return v, "malicious"


MALICIOUS_PATTERNS = [dropper_execute_c2, persistence_unsigned, reverse_shell, data_exfiltration]


# ---------------------------------------------------------------------------
# Suspicious patterns
# ---------------------------------------------------------------------------

def unsigned_shell_no_network():
    """Unsigned shell running, but no network activity yet."""
    v = zero_vec()
    v[idx("process_is_unsigned")]          = 1
    v[idx("process_is_shell")]             = 1
    v[idx("process_parent_chain_depth")]   = random.randint(1, 4)
    v[idx("process_age_seconds")]          = random.uniform(0, 30)
    v[idx("fs_file_entropy")]              = random.uniform(5.0, 7.5)
    v[idx("temporal_signals_in_window")]   = random.randint(1, 5)
    v[idx("temporal_unique_monitors_firing")] = random.randint(1, 2)
    return v, "suspicious"


def new_persistence_signed():
    """New LaunchAgent written, but the target binary is signed."""
    v = zero_vec()
    v[idx("persist_new_launchagent")]      = 1
    v[idx("temporal_signals_in_window")]   = random.randint(1, 4)
    v[idx("temporal_unique_monitors_firing")] = 1
    return v, "suspicious"


SUSPICIOUS_PATTERNS = [unsigned_shell_no_network, new_persistence_signed]


def add_noise(vec, noise_level=0.05):
    """Add small random noise to numeric features to improve generalization."""
    return [
        max(0.0, v + random.gauss(0, noise_level)) if i not in (0,1,2,3,4,5,6,9,10,11,13,14,16,17,19,20,21,22,23,24,25,26,27,28,31,32,33,34,39)
        else v
        for i, v in enumerate(vec)
    ]


def generate(n_samples: int, benign_ratio: float, malicious_ratio: float):
    rows = []
    n_benign    = int(n_samples * benign_ratio)
    n_malicious = int(n_samples * malicious_ratio)
    n_suspicious = n_samples - n_benign - n_malicious

    for _ in range(n_benign):
        fn = random.choice(BENIGN_PATTERNS)
        vec, label = fn()
        rows.append((add_noise(vec), label))

    for _ in range(n_malicious):
        fn = random.choice(MALICIOUS_PATTERNS)
        vec, label = fn()
        rows.append((add_noise(vec, noise_level=0.02), label))

    for _ in range(n_suspicious):
        fn = random.choice(SUSPICIOUS_PATTERNS)
        vec, label = fn()
        rows.append((add_noise(vec), label))

    random.shuffle(rows)
    return rows


def main():
    parser = argparse.ArgumentParser(description="Generate Nick behavioral threat training data")
    parser.add_argument("--output",   default="training_data.csv", help="Output CSV path")
    parser.add_argument("--samples",  type=int, default=5000,       help="Total number of samples")
    parser.add_argument("--benign",   type=float, default=0.50,     help="Fraction of benign samples")
    parser.add_argument("--malicious",type=float, default=0.30,     help="Fraction of malicious samples")
    parser.add_argument("--seed",     type=int, default=42,         help="Random seed for reproducibility")
    args = parser.parse_args()

    if args.benign + args.malicious > 1.0:
        print("ERROR: benign + malicious fractions must not exceed 1.0", file=sys.stderr)
        sys.exit(1)

    random.seed(args.seed)

    print(f"Generating {args.samples} samples "
          f"({int(args.samples*args.benign)} benign, "
          f"{int(args.samples*args.malicious)} malicious, "
          f"{args.samples - int(args.samples*args.benign) - int(args.samples*args.malicious)} suspicious)...")

    rows = generate(args.samples, args.benign, args.malicious)

    output_path = Path(args.output)
    with output_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ["label"])
        for vec, label in rows:
            writer.writerow([f"{v:.6f}" for v in vec] + [label])

    print(f"Wrote {len(rows)} rows to {output_path}")


if __name__ == "__main__":
    main()
