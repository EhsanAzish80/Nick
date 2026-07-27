# Nick — Training Pipeline

**Maintainer:** Ehsan Azish ([@ehsanazish80](https://github.com/EhsanAzish80))
**Repository:** [github.com/EhsanAzish80/Nick](https://github.com/EhsanAzish80/Nick)

## Overview

This directory contains the Python pipeline for training Nick's on-device CoreML
behavioral threat scoring model. The model uses a Gradient Boosted Tree (GBT)
classifier trained on 40-dimensional feature vectors extracted from macOS process,
network, file system, persistence, and YARA signals.

## Prerequisites

```bash
pip install scikit-learn coremltools pandas numpy
```

Python 3.10+ required. Tested with scikit-learn 1.4+ and coremltools 7+.

## Files

| File | Purpose |
|------|---------|
| `feature_schema.json` | Canonical 40-feature schema — source of truth for both Swift and Python |
| `generate_training_data.py` | Generates synthetic labeled training data |
| `train_model.py` | Trains GBT classifier and converts to CoreML |

Generated CSV files are always written inside this directory. The pipeline does
not load serialized Python models because pickle deserialization can execute
arbitrary code. Evaluation and Core ML conversion happen directly in
`train_model.py` while the trained model remains in memory.

## Quickstart

```bash
# 1. Generate synthetic training data (5000 samples)
python3 generate_training_data.py --samples 5000

# 2. Train the model and produce ThreatScorer.mlmodel
python3 train_model.py --data training_data.csv --output ThreatScorer.mlmodel

# 3. Copy the model into the Xcode project
cp ThreatScorer.mlmodel ../../Nick/Resources/ThreatScorer.mlmodel
```

## Feature Vector

The model takes a 40-dimensional feature vector. See `feature_schema.json` for
the full definition. Key groups:

- **Process (0–9):** Signing status, execution path, parent chain, LOLBin detection
- **Network (10–16):** Outbound connections, raw IP addresses, port analysis
- **File System (17–23):** Entropy, Mach-O detection, embedded URLs/base64
- **Persistence (24–28):** LaunchAgent/Daemon/cron additions, unsigned targets
- **YARA (29–30):** Match count and max severity
- **System Audit (31–34):** SIP, FileVault, Gatekeeper, Firewall state
- **Temporal (35–39):** Signal timing, window density, severity escalation

## Model Architecture

- **Algorithm:** `sklearn.ensemble.GradientBoostingClassifier`
- **Classes:** `benign` (0), `suspicious` (1), `malicious` (2)
- **Output in CoreML:** `threatLabel` (class), `threatLabelProbability` (dict)
- **Swift usage:** See `BehavioralScorer.swift` — extracts malicious probability

## Performance Targets

| Metric | Target |
|--------|--------|
| Precision (malicious) | ≥ 90% |
| Recall (malicious) | ≥ 85% |
| CoreML inference time | < 5ms |
| Model file size | < 1 MB |

## Training Methodology

Synthetic data is generated from known attack and benign behavioral patterns:

**Benign:** Homebrew installs, Xcode builds, npm/pip installs, browser downloads.

**Malicious:**
- Dropper → execute → C2 (unsigned binary in /tmp + raw IP outbound)
- Persistence installer (LaunchAgent + unsigned target)
- Reverse shell (shell process + raw IP on high port)
- Data exfiltration (high entropy + base64 + uncommon port)

**Suspicious:** Patterns that are ambiguous without more context.

Small Gaussian noise is added to numeric features to improve generalization.

## Adding Real Labeled Data

Export real detections from Nick using `TrainingDataExporter.swift`,
have a security analyst label them as `benign`/`suspicious`/`malicious`,
then merge with the synthetic CSV and retrain.

## Updating the Model

After training, add `ThreatScorer.mlmodel` to the Xcode project under
`Nick/Resources/` and ensure it's in the `Nick` target membership.
Xcode auto-generates the `ThreatScorer` Swift class on build.
