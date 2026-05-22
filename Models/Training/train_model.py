#!/usr/bin/env python3
"""
Nick — CoreML Threat Scoring Model Trainer
Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
Licensed under AGPL-3.0. See LICENSE for details.

Trains a Gradient Boosted Tree classifier on labeled behavioral feature vectors
and exports the model as a CoreML .mlmodel file for on-device inference.

Usage:
    python3 train_model.py --data training_data.csv --output ThreatScorer.mlmodel

Requirements:
    pip install scikit-learn coremltools pandas numpy
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)
from sklearn.preprocessing import LabelEncoder
import coremltools as ct
from coremltools.models.pipeline import Pipeline


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

LABEL_COLUMN = "label"

# Map multi-class labels to binary threat probability targets
# For the CoreML model we output a single probability (0.0 = benign, 1.0 = malicious)
LABEL_TO_THREAT = {"benign": 0, "suspicious": 0.5, "malicious": 1}
BINARY_THRESHOLD = 0.4  # above this → "threat" for metrics purposes


def load_data(csv_path: Path):
    df = pd.read_csv(csv_path)
    missing = set(FEATURE_NAMES) - set(df.columns)
    if missing:
        print(f"ERROR: CSV is missing features: {missing}", file=sys.stderr)
        sys.exit(1)

    X = df[FEATURE_NAMES].values.astype(np.float32)
    # Map labels to binary for regression-style GBT
    y_raw = df[LABEL_COLUMN].map({"benign": 0, "suspicious": 1, "malicious": 2}).values
    y_labels = df[LABEL_COLUMN].values
    return X, y_raw, y_labels


def train(X_train, y_train):
    model = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.8,
        min_samples_leaf=10,
        random_state=42,
        n_iter_no_change=15,
        validation_fraction=0.1,
        verbose=0,
    )
    print("Training Gradient Boosted Tree...")
    t0 = time.time()
    model.fit(X_train, y_train)
    print(f"Training completed in {time.time() - t0:.1f}s")
    return model


def evaluate(model, X_test, y_test, y_labels_test):
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)

    label_names = ["benign", "suspicious", "malicious"]
    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=label_names, zero_division=0))

    # Binary malicious vs not-malicious metrics (primary concern)
    y_binary_true = (y_test == 2).astype(int)
    y_binary_pred = (y_pred == 2).astype(int)
    y_binary_prob = y_prob[:, 2]

    precision = precision_score(y_binary_true, y_binary_pred, zero_division=0)
    recall    = recall_score(y_binary_true, y_binary_pred, zero_division=0)
    f1        = f1_score(y_binary_true, y_binary_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_binary_true, y_binary_prob)
    except ValueError:
        auc = 0.0

    print(f"\n=== Malicious Detection Metrics ===")
    print(f"  Precision : {precision:.3f}  (target ≥ 0.90)")
    print(f"  Recall    : {recall:.3f}  (target ≥ 0.85)")
    print(f"  F1        : {f1:.3f}")
    print(f"  ROC-AUC   : {auc:.3f}")

    if precision < 0.90:
        print("  ⚠ WARNING: Precision below target. Consider more training data or tuning.")
    if recall < 0.85:
        print("  ⚠ WARNING: Recall below target. Consider more training data or tuning.")

    # Feature importance
    importances = model.feature_importances_
    ranked = sorted(zip(FEATURE_NAMES, importances), key=lambda x: -x[1])
    print("\n=== Top 10 Feature Importances ===")
    for name, imp in ranked[:10]:
        bar = "█" * int(imp * 100)
        print(f"  {name:<45} {imp:.4f}  {bar}")

    # Benchmark inference speed
    t0 = time.perf_counter()
    for _ in range(1000):
        _ = model.predict_proba(X_test[:1])
    elapsed_ms = (time.perf_counter() - t0)
    per_inference_ms = elapsed_ms

    print(f"\n=== Inference Speed ===")
    print(f"  1000 inferences in {elapsed_ms*1000:.1f}ms → {per_inference_ms:.4f}ms per call")
    if per_inference_ms > 0.005:
        print("  ⚠ WARNING: Inference may exceed 5ms target on slower devices.")

    return precision, recall, f1


def convert_to_coreml(model, output_path: Path):
    """Convert sklearn GBT model to CoreML .mlmodel format."""
    import coremltools as ct
    from coremltools.converters.sklearn import convert as sklearn_convert

    print(f"\nConverting to CoreML: {output_path}")

    coreml_model = ct.converters.sklearn.convert(
        model,
        input_features=[(name, ct.models.datatypes.Double()) for name in FEATURE_NAMES],
        output_feature_names="threatLabel",
    )

    # Add metadata
    coreml_model.short_description = "Nick behavioral threat scoring model. Outputs threat probability 0.0–1.0."
    coreml_model.author  = "Ehsan Azish — github.com/EhsanAzish80"
    coreml_model.license = "AGPL-3.0"
    coreml_model.version = "1.0.0"
    coreml_model.input_description["threatLabel"] = "Predicted threat class (0=benign, 1=suspicious, 2=malicious)"

    coreml_model.save(str(output_path))

    model_size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"Saved CoreML model ({model_size_mb:.2f} MB) → {output_path}")
    if model_size_mb > 1.0:
        print("  ⚠ WARNING: Model exceeds 1 MB target. Consider reducing n_estimators or max_depth.")


def save_feature_importances(model, output_dir: Path):
    importances = dict(zip(FEATURE_NAMES, model.feature_importances_.tolist()))
    out = output_dir / "feature_importances.json"
    with out.open("w") as f:
        json.dump(importances, f, indent=2)
    print(f"Feature importances written to {out}")


def main():
    parser = argparse.ArgumentParser(description="Train Nick behavioral threat scoring model")
    parser.add_argument("--data",   default="training_data.csv",   help="Path to labeled CSV training data")
    parser.add_argument("--output", default="ThreatScorer.mlmodel", help="Output CoreML model path")
    args = parser.parse_args()

    data_path   = Path(args.data)
    output_path = Path(args.output)

    if not data_path.exists():
        print(f"ERROR: Training data not found: {data_path}", file=sys.stderr)
        print("Run generate_training_data.py first.", file=sys.stderr)
        sys.exit(1)

    X, y, y_labels = load_data(data_path)
    print(f"Loaded {len(X)} samples with {X.shape[1]} features")
    unique, counts = np.unique(y, return_counts=True)
    for cls, cnt in zip(["benign", "suspicious", "malicious"], counts if len(counts) == 3 else [0]*3):
        print(f"  {cls}: {cnt}")

    # Split: 70% train, 15% validation (used by GBT internally), 15% test
    X_train, X_test, y_train, y_test, _, y_labels_test = train_test_split(
        X, y, y_labels, test_size=0.15, random_state=42, stratify=y
    )

    model = train(X_train, y_train)
    precision, recall, f1 = evaluate(model, X_test, y_test, y_labels_test)

    convert_to_coreml(model, output_path)
    save_feature_importances(model, output_path.parent)

    print("\n✓ Training complete.")
    if precision >= 0.90 and recall >= 0.85:
        print("✓ Performance targets met.")
    else:
        print("✗ One or more performance targets not met. Review data quality and re-run.")


if __name__ == "__main__":
    main()
