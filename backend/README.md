# Backend README (backend/README.md)Markdown# Backend — AI-Based IDS

Python backend handling packet capture, AI inference, alert streaming, and the Flask/Socket.IO dashboard API.

---

## Model Performance (CICIDS2017 Friday DDoS — held-out test set)

| Model | Accuracy | Precision | Recall | F1 |
| --- | --- | --- | --- | --- |
| Autoencoder | — | — | — | ROC-AUC 0.79 |
| Random Forest | 99.75% | 99.26% | 99.74% | **99.50%** |
| CNN | 99.76% | 99.12% | 99.91% | **99.51%** |

Calibrated reconstruction threshold: `0.003154` (90th percentile of benign errors).
Random Forest false positive rate: **0.25%** (84 / 33,790 benign flows).

These are held-out offline results for the documented CICIDS2017 Friday-Afternoon DDoS evaluation. The CNN is not used for live packet scoring: it expects 100-flow row-ordered sequences. Its current confusion matrix covers 4,505 sequence samples, while the general metrics artifact records 45,149 rows for the broader evaluation context; do not present those as identical sample counts.

---

## Setup

```bash
pip install -r requirements.txt
```

CommandsPreprocess dataset:Bashpython main.py --mode preprocess --dataset "data/<cicids-file>.csv" --multiclass
Train models:

```Bash
python run_training.py
```

Use this, not main.py --mode train — avoids a Windows joblib deadlock caused by Flask/SocketIO loading during cross-validation.

Evaluate metrics:

```bash
python src/model_evaluation.py data/preprocessed/CICIDS2017_cleaned.csv
```

Run Flask server:

```bash
python main.py
```

Verify end-to-end pipeline:

```bash
python verify_ensemble.py
```

Calibrate override thresholds:

```bash
python src/calibrate_override.py
```

Tests:

```bash
python -m pytest tests/ -v
```

## Automated Tests

The suite covers preprocessing, live flow scoring, route security, threat-intel privacy, and sequence construction. Model-backed inference and scaler-alignment tests require artifacts under backend/models. CI downloads those artifacts and fails if any test is skipped.

Structure

```
backend/
├── main.py                      # Flask server + IDS entry point
├── run_training.py              # Standalone training script
├── verify_ensemble.py           # End-to-end pipeline check
├── src/
│   ├── ids_pipeline.py          # Real-time AI engine (AE + RF ensemble)
│   ├── data_preprocessing.py    # CICIDS2017 cleaning + MinMax scaling
│   ├── sequence_builder.py      # CNN sliding-window sequence builder
│   ├── ai_model_development.py  # Model architectures + training
│   ├── model_evaluation.py      # Metrics → real_metrics.json
│   └── calibrate_override.py    # Data-driven override threshold calibration
├── models/
│   ├── autoencoder.h5
│   ├── random_forest.pkl
│   ├── cnn_classifier.h5
│   ├── feature_scaler.pkl
│   ├── label_map.json           # {0: "Benign", 1: "DDoS"}
│   └── real_metrics.json
├── tests/
│   ├── conftest.py
│   ├── test_preprocessing.py
│   ├── test_model_training.py
│   ├── test_inference.py
│   ├── test_feature_alignment.py
│   └── test_proposed_block_queue.py
└── data/
    └── preprocessed/
        └── CICIDS2017_cleaned.csv
```

---

## Known Limitations

* Live extraction emits 78 columns in scaler order, but only a subset has CICFlowMeter-equivalent measurements; unsupported values are zero-filled, so full feature parity and offline-equivalent live accuracy are not claimed.
* RF classifies real CICIDS2017 vectors correctly but predicts Benign on Scapy-captured flows.
* The AE override handles live detection for those cases.
* CNN is offline-only — requires 100-flow ordered windows unavailable in per-flow live capture.
* run_training.py must be used on Windows instead of main.py --mode train to avoid joblib deadlock.
