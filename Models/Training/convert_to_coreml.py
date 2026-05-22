#!/usr/bin/env python3
"""
Nick — CoreML Conversion Script
Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
Licensed under AGPL-3.0. See LICENSE for details.

Converts a trained scikit-learn model (pickle) to CoreML .mlmodel format.
Run this after train_model.py if you want to re-convert without retraining.

Usage:
    python3 convert_to_coreml.py --model model.pkl --output ThreatScorer.mlmodel
"""

import argparse
import pickle
import sys
from pathlib import Path

import coremltools as ct

FEATURE_NAMES = [
    "process_is_unsigned", "process_is_adhoc_signed", "process_in_tmp",
    "process_in_hidden_dir", "process_is_shell", "process_parent_is_gui_app",
    "process_parent_is_terminal", "process_parent_chain_depth", "process_age_seconds",
    "process_is_lolbin", "net_has_outbound_connection", "net_remote_is_raw_ip",
    "net_remote_port", "net_remote_port_is_common", "net_is_listening",
    "net_connection_count", "net_uses_uncommon_port", "fs_file_in_tmp",
    "fs_file_entropy", "fs_file_entropy_is_high", "fs_file_is_macho",
    "fs_file_has_embedded_urls", "fs_file_has_embedded_base64",
    "fs_rapid_creation_detected", "persist_new_launchagent",
    "persist_new_launchdaemon", "persist_new_cronjob",
    "persist_executable_unsigned", "persist_executable_missing",
    "yara_match_count", "yara_max_severity", "audit_sip_disabled",
    "audit_filevault_disabled", "audit_gatekeeper_disabled",
    "audit_firewall_disabled", "temporal_time_since_file_creation",
    "temporal_time_since_net_connection", "temporal_signals_in_window",
    "temporal_unique_monitors_firing", "temporal_severity_escalation",
]


def main():
    parser = argparse.ArgumentParser(description="Convert sklearn model to CoreML")
    parser.add_argument("--model",  required=True, help="Path to trained sklearn model pickle")
    parser.add_argument("--output", default="ThreatScorer.mlmodel", help="Output .mlmodel path")
    args = parser.parse_args()

    model_path  = Path(args.model)
    output_path = Path(args.output)

    if not model_path.exists():
        print(f"ERROR: Model not found: {model_path}", file=sys.stderr)
        sys.exit(1)

    with model_path.open("rb") as f:
        model = pickle.load(f)

    coreml_model = ct.converters.sklearn.convert(
        model,
        input_features=[(name, ct.models.datatypes.Double()) for name in FEATURE_NAMES],
        output_feature_names="threatLabel",
    )

    coreml_model.short_description = "Nick behavioral threat scoring model."
    coreml_model.author  = "Ehsan Azish — github.com/EhsanAzish80"
    coreml_model.license = "AGPL-3.0"
    coreml_model.version = "1.0.0"

    coreml_model.save(str(output_path))

    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"Saved: {output_path} ({size_mb:.2f} MB)")


if __name__ == "__main__":
    main()
