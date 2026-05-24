#!/usr/bin/env python3
"""
Nick — Model Evaluation Script
Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
Licensed under AGPL-3.0. See LICENSE for details.

Standalone evaluation with confusion matrix output.
Loads a trained sklearn model (pickle) and evaluates against a held-out test set.

Usage:
    python3 evaluate_model.py --model model.pkl --data test_data.csv
"""

import argparse
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score, roc_auc_score
)

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

LABEL_MAP = {"benign": 0, "suspicious": 1, "malicious": 2}
LABEL_NAMES = ["benign", "suspicious", "malicious"]


def print_confusion_matrix(cm, label_names):
    print("\n=== Confusion Matrix ===")
    header = "         " + "  ".join(f"{n:>10}" for n in label_names)
    print(header)
    for i, row in enumerate(cm):
        row_str = "  ".join(f"{v:>10}" for v in row)
        print("{label_names[i]:>8} {row_str}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate Nick threat scoring model")
    parser.add_argument("--model", required=True, help="Path to trained model pickle")
    parser.add_argument("--data",  required=True, help="Path to labeled CSV test data")
    args = parser.parse_args()

    model_path = Path(args.model)
    data_path  = Path(args.data)

    if not model_path.exists():
        print("ERROR: Model not found: {model_path}", file=sys.stderr)
        sys.exit(1)
    if not data_path.exists():
        print("ERROR: Data not found: {data_path}", file=sys.stderr)
        sys.exit(1)

    with model_path.open("rb") as f:
        model = pickle.load(f)

    df = pd.read_csv(data_path)
    X  = df[FEATURE_NAMES].values.astype(np.float32)
    y  = df["label"].map(LABEL_MAP).values

    y_pred = model.predict(X)
    y_prob = model.predict_proba(X)

    print("Evaluated {len(X)} samples")
    print(classification_report(y, y_pred, target_names=LABEL_NAMES, zero_division=0))

    cm = confusion_matrix(y, y_pred)
    print_confusion_matrix(cm, LABEL_NAMES)

    y_binary_true = (y == 2).astype(int)
    y_binary_pred = (y_pred == 2).astype(int)
    y_binary_prob = y_prob[:, 2]

    precision = precision_score(y_binary_true, y_binary_pred, zero_division=0)
    recall    = recall_score(y_binary_true, y_binary_pred, zero_division=0)
    f1        = f1_score(y_binary_true, y_binary_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_binary_true, y_binary_prob)
    except ValueError:
        auc = 0.0

    print("\n=== Malicious Detection (binary) ===")
    print("  Precision : {precision:.3f}")
    print("  Recall    : {recall:.3f}")
    print("  F1        : {f1:.3f}")
    print("  ROC-AUC   : {auc:.3f}")


if __name__ == "__main__":
    main()
