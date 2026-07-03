1. Backend README (backend/README.md)Markdown# Backend — AI-Based IDS

Python backend handling packet capture, AI inference, alert streaming, and the Flask/Socket.IO dashboard API.

---

## Model Performance (CICIDS2017 Friday DDoS — held-out test set)

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Autoencoder | — | — | — | ROC-AUC 0.79 |
| Random Forest | 99.75% | 99.26% | 99.74% | **99.50%** |
| CNN | 99.76% | 99.12% | 99.91% | **99.51%** |

Calibrated reconstruction threshold: `0.003154` (90th percentile of benign errors).
Random Forest false positive rate: **0.25%** (84 / 33,790 benign flows).

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
```Bash
python src/model_evaluation.py data/preprocessed/CICIDS2017_cleaned.csv
```

Run Flask server:
```Bash
python main.py
```

Verify end-to-end pipeline:
```Bash
python verify_ensemble.py
```

Calibrate override thresholds:
```Bash
python src/calibrate_override.py
```

Tests
```Bash
python -m pytest tests/ -v
```
```
File,Count,Covers
test_preprocessing.py,4,"Inf removal, MinMax range, label encoding, text column drop"
test_model_training.py,5,"Window shape, ordering, last-row label, small-split error, leakage regression"
test_inference.py,11,"Scoring, overrides, alert gating, threat name propagation"
```

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
│   └── test_inference.py
└── data/
    └── preprocessed/
        └── CICIDS2017_cleaned.csv
```
Known LimitationsLive feature extraction covers ~24 of 78 CICIDS2017 features; remaining are zero-filled. RF classifies real CICIDS2017 vectors correctly but predicts Benign on Scapy-captured flows.The AE override handles live detection for those cases.CNN is offline-only — requires 100-flow ordered windows unavailable in per-flow live capture.run_training.py must be used on Windows instead of main.py --mode train to avoid joblib deadlock.
