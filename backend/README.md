# Backend — AI-Based IDS

Python backend for packet capture, flow feature extraction, AE + RF inference, alert streaming over Redis, and the Flask/Socket.IO dashboard API.

## Model performance

CICIDS2017 Friday-Afternoon DDoS, held-out test split. Source of truth: `models/real_metrics.json` (written by `src/model_evaluation.py`).

| Model         | Test samples      | Accuracy | Precision | Recall | F1     | ROC-AUC | Live? |
|---------------|-------------------|---------:|----------:|-------:|-------:|--------:|-------|
| Autoencoder   | 45,149 flows      | 78.87%   | 59.78%    | 48.88% | 53.78% | 0.791   | Yes (fusion) |
| Random Forest | 45,149 flows      | 99.75%   | 99.26%    | 99.74% | 99.50% | —       | Yes (fusion) |
| CNN           | 4,505 sequences   | 99.76%   | 99.12%    | 99.91% | 99.51% | —       | No (offline only) |

- **AE threshold:** 0.003154 reconstruction error (90th percentile of benign *training* errors). At this threshold the AE misses 5,807 of 11,359 attack flows and false-alarms on 3,735 of 33,790 benign flows — it is weak on its own and is used only as one input to the fusion layer.
- **RF false-positive rate:** 0.25% (84 / 33,790 benign flows).
- **CNN** is evaluated on 100-flow windows (stride 10) built from the same held-out split. Its sample count differs from the flow-level rows, so the numbers are not directly comparable.

These are offline results on one CICIDS2017 day. They are not live detection accuracy. Live attack detection is not yet demonstrated; see "Live detection status" in the root README.

## Setup

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env        # then set ABUSEIPDB_API_KEY, REDIS_PASSWORD, etc.
```

Trained models are gitignored. Either train them (below) or download them from the `v1.0-models` GitHub release into `models/`.

## Commands

```bash
# Preprocess dataset
python main.py --mode preprocess --dataset "data/CICIDS2017/Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv"
```
```bash
# Train models — use this, not `main.py --mode train`
# (avoids a Windows joblib deadlock caused by Flask/Socket.IO loading during cross-validation)
python run_training.py
```
```bash
# Evaluate -> models/real_metrics.json
python src/model_evaluation.py data/preprocessed/CICIDS2017_cleaned.csv
```
```bash
# Dashboard + API server (default mode)
python main.py
```
```bash
# Live capture + detection (Administrator / root; separate process)
python main.py --mode ids --interface auto
```
```bash
# Synthetic end-to-end fusion check (not live evidence)
python verify_ensemble.py
```
```bash
# Calibrate AE/RF override thresholds from benign traffic
python src/calibrate_override.py
```
```bash
# Tests
python -m pytest tests/ -v
```

`main.py --mode` accepts `preprocess`, `train`, `ids`, `dashboard`.

## Tests

The suite covers preprocessing, sequence construction and leakage, live flow scoring and feature parity (including CICFlowMeter reference fixtures), inference/fusion, route security and auth, threat-intel privacy, whitelist, and the proposed-block queue.

Model-backed tests (e.g. `test_inference.py`) need real artifacts in `models/` and skip without them. CI (`.github/workflows/backend-tests.yml`) downloads the `v1.0-models` release and **fails the build if any test is skipped**, so a green CI run means the model-backed tests actually ran.

## Structure

```
backend/
├── main.py                       # CLI entry: dashboard / ids / preprocess / train
├── routes.py                     # Flask REST API (/api/*)
├── run_training.py               # Standalone training (Windows-safe)
├── verify_ensemble.py            # Synthetic end-to-end fusion check
├── evaluate_ddos_heldout.py      # Held-out RF / AE / fusion evaluation
├── benchmark_live_pipeline.py    # Live pipeline latency/throughput benchmark
├── validate_live_capture.py      # Gate before enabling AE-only alerting
├── skew_report.py                # Live vs training feature skew report
├── src/
│   ├── ids_pipeline.py           # Capture, flow features, AE + RF fusion, alerting
│   ├── data_preprocessing.py     # CICIDS2017 cleaning + scaling
│   ├── sequence_builder.py       # CNN sliding-window sequences (offline)
│   ├── ai_model_development.py   # Model architectures + training
│   ├── model_evaluation.py       # Metrics -> models/real_metrics.json
│   ├── model_artifacts.py        # Artifact loading / validation
│   ├── calibrate_override.py     # Override threshold calibration (CSV)
│   ├── calibrate_override_live.py# Override calibration on live benign traffic
│   ├── scoring.py                # Severity bands / settings defaults
│   ├── redis_alert_bridge.py     # Redis stream -> Socket.IO
│   ├── redis_util.py
│   ├── threat_intel_service.py   # AbuseIPDB lookups
│   ├── threat_evidence.py        # Evidence files (alerts.jsonl, screenshots)
│   ├── system_status.py
│   ├── network_utils.py
│   └── geo_utils.py
├── models/                       # *.h5 / *.pkl gitignored; real_metrics.json tracked
│   ├── autoencoder.h5
│   ├── random_forest.pkl
│   ├── cnn_classifier.h5
│   ├── feature_scaler.pkl
│   ├── label_map.json            # {0: "Benign", 1: "DDoS"}
│   └── real_metrics.json
├── tests/                        # pytest suite (see above)
└── data/                         # CICIDS2017 CSVs — not in the repo
```

## Known limitations

- **Feature parity is not proven.** The live extractor emits the 78 CICFlowMeter V4 features in scaler order, but the exact CICFlowMeter revision/JAR that produced the training CSV is not preserved, so implementation-level parity has not been independently established. Offline metrics must not be read as live detection accuracy. Use `skew_report.py` to measure drift on captured traffic.
- **AE-only alerting is off by default.** It is enabled only after `validate_live_capture.py` passes on labelled live-lab data (`IDS_AE_ONLY_ALERTING_VALIDATED=true`). Live capture refuses to start without `random_forest.pkl` unless that flag is set.
- **CNN is offline-only.** It needs 100-flow ordered windows that per-flow live capture does not provide.
- **Windows:** use `run_training.py` instead of `main.py --mode train`.
