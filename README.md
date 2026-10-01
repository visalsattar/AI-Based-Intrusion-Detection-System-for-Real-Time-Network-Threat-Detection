# AI-Based Intrusion Detection System (IDS)

**Final Year Project — BS Computer Science, The University of Agriculture, Peshawar**

A network intrusion detection system that monitors live traffic and scores flows in real time with a fused **Random Forest + Autoencoder** pipeline. A third model, a **CNN**, was trained and evaluated offline for architecture comparison only. It is **not** part of the live detection path (see [Why the CNN doesn't run live](#why-the-cnn-doesnt-run-live)).

> **Status: live attack detection is NOT yet demonstrated.** The pipeline runs end to end on live traffic (capture → features → models → Redis → dashboard), and the models score well on the offline CICIDS2017 test split. In controlled lab runs, however, the system did not alert on a LAN TCP connect+GET flood, because that flood does not resemble the training attack's flow profile. See [Live detection status](#live-detection-status).

## The problem

Signature-based detection only catches attack patterns already on a list. This system combines a supervised classifier (Random Forest, for known attacks) with an Autoencoder trained on benign traffic (flags flows that deviate from normal), so it has a path to flag traffic that matches no known signature. In practice the Autoencoder is weak on its own (F1 53.78% offline), and alerts from it alone are **disabled by default** until validated on live-lab traffic.

## Highlights

- Two models fused for live detection; a CNN built and benchmarked offline as an architecture comparison
- Trained and evaluated on 225,745 real CICIDS2017 flows (Friday DDoS capture)
- Full stack: Scapy capture → feature extraction → ML fusion → Redis Streams → Flask/Socket.IO → React dashboard, packaged with Docker
- Automated pytest suite covering preprocessing, sequence construction and train/test leakage, inference/fusion logic, flow scoring, route security, threat-intel privacy, whitelist and AutoBlock behaviour
- The Autoencoder's weak standalone metrics are reported below, not omitted

## How it works

```
Network Traffic
      │
      ▼
┌─────────────┐    ┌──────────────────┐    ┌──────────────────────────┐
│   Packet    │    │    Feature       │    │    Live Fusion           │
│   Capture   │───▶│    Extraction    │───▶│                          │
│   (Scapy)   │    │  (78 CICIDS2017  │    │  Autoencoder (AE)        │
└─────────────┘    │    features)     │    │  + Random Forest (RF)    │
                   └──────────────────┘    │                          │
                                           │  score = 0.5×AE + 0.5×RF │
                                           └────────────┬─────────────┘
                                                        │
                                                        ▼
                                           ┌──────────────────────────┐
                                           │    Alert Engine          │
                                           │  (Redis stream ids:alerts)│
                                           └────────────┬─────────────┘
                                                        │
                                                        ▼
                                           ┌──────────────────────────┐
                                           │    React Dashboard       │
                                           │  (Flask + Socket.IO)     │
                                           └──────────────────────────┘
```

**Fusion logic** (`backend/src/ids_pipeline.py`):

- `fused = 0.5 × AE anomaly score + 0.5 × RF attack probability`, where AE score = `e / (e + threshold)`
- Overrides: if AE score > **0.97** or RF probability > **0.90**, the alert score becomes the larger of the fused score and that model's score
- An alert fires when the alert score exceeds the cutoff set by the Settings sensitivity: **0.85** at medium (default, `alert_threshold` in `main.py`), 0.95 at low, 0.70 at high
- Without `random_forest.pkl`, AE-only results are suppressed unless `IDS_AE_ONLY_ALERTING_VALIDATED=true`

The 0.97 / 0.90 overrides are coded defaults; `backend/src/calibrate_override.py` can replace them with values calibrated on benign traffic.

### Why the CNN doesn't run live

The CNN classifies sequences of 100 consecutive flows. That window only has meaning on the row-ordered CICIDS2017 CSV used for offline evaluation; live per-flow capture provides no equivalent temporal window, so feeding it live data would be out-of-distribution input. It was trained, benchmarked and documented, then deliberately kept out of the live path.

## Model performance

Held-out DDoS/benign flow-level evaluation:

| Model / path   | Accuracy | Precision | Recall | F1     | Role               |
|----------------|---------:|----------:|-------:|-------:|--------------------|
| Random Forest  | 99.75%   | 99.26%    | 99.74% | 99.50% | Live fusion        |
| Autoencoder    | 78.87%   | 59.78%    | 48.88% | 53.78% | Live fusion        |
| RF + AE fusion, live gate (> 0.85 + overrides) | 99.84% | 99.98% | 99.40% | 99.69% | Live decision rule, scored offline |
| RF + AE fusion, cutoff 0.5 + overrides | 99.60% | 98.90% | 99.51% | 99.20% | Diagnostic only |
| CNN            | 99.76%   | 99.12%    | 99.91% | 99.51% | Offline only       |

- All rows are **offline** results on the 45,149-row held-out flow-level test split (chronological last 20%, no shuffle; ~25% DDoS). RF and AE rows come from `backend/models/real_metrics.json`.
- The cutoff-0.5 fusion row comes from `backend/evaluate_ddos_heldout.py`. It is **not** the live rule: live alerts need a score above 0.85 at the default sensitivity. The live-gate row applies the actual rule from `ids_pipeline.py` to the same split (recomputed 2026-10-01, Windows, Python 3.11; see `PROGRESS.md`). At high sensitivity (> 0.70) F1 is 99.35%; at low (> 0.95) it is 99.64%.
- The CNN result uses a separate 4,505-sequence subset (100-row windows, stride 10). It is **not** directly comparable to the flow-level rows.
- These are experiment-specific results on one CICIDS2017 day (DDoS vs benign). They are not cross-dataset validation, not evidence for other CICIDS2017 attack families, and not a guarantee of live-network accuracy.
- Training data is one binary task, DDoS vs benign. No PortScan, brute-force, web-attack or botnet detection is claimed.
- The live extractor produces the full 78-feature input contract, but exact numerical equivalence with the CICFlowMeter (Java) build that generated the training CSV has not been established. The reference fixtures in `backend/tests/` are hand-calculated from CICFlowMeter V4 semantics; Java was not executed.
- Known train/serve fixes in the live path: the six Bulk features are forced to 0 (always 0 in training); flag-count features are clamped to 0/1 (0/1 in training); Subflow features equal the flow totals (as in training); Active/Idle use the 5 s activity timeout found in the training data. Several features are still always 0 live but non-zero in training (for example the packet-length minimums and the Idle statistics).

## Setup

### Prerequisites

- Python 3.11
- Node.js 20 LTS
- Redis (local install on port 6379, **or** the Docker Compose service — see below)
- Npcap (live packet capture on Windows)

**Dataset:** CICIDS2017 is not included (too large for GitHub). Download `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (lowercase "os", as CIC names it) from the official CIC dataset page and place it in `backend/data/CICIDS2017/` if you plan to preprocess or retrain.

**Configuration:** copy `.env.example` → `.env` (repo root, used by Docker Compose; must set `REDIS_PASSWORD`) and `backend/.env.example` → `backend/.env`.

### Install dependencies

```bash
# Backend
cd backend
pip install -r requirements.txt
```
```bash
# Frontend
cd frontend
npm install
```

### Model artifacts

Trained model files (`*.h5`, `*.pkl`) are gitignored and are **not** in this repository. Generate them with the training steps below and keep them in `backend/models/`:

`autoencoder.h5`, `random_forest.pkl`, `cnn_classifier.h5`, `feature_scaler.pkl`, `label_map.json`

Live capture refuses to start without `random_forest.pkl` unless validated AE-only alerting is explicitly enabled.

### Train from scratch

```bash
cd backend
```
```bash
# 1. Preprocess the dataset (first time only)
python main.py --mode preprocess --dataset "data/CICIDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
```
```bash
# 2. Train models
#    Use run_training.py, not `main.py --mode train` — avoids a Windows joblib deadlock.
python run_training.py
```
```bash
# 3. Evaluate
python src/model_evaluation.py data/preprocessed/CICIDS2017_cleaned.csv
```

## Running the system

### Local (without Docker)

```bash
# Dashboard + API (default mode is `dashboard`)
cd backend
python main.py
```
```bash
# Packet capture + detection — separate terminal, Administrator required
cd backend
python main.py --mode ids --interface auto
```
```bash
# React dev server — separate terminal
cd frontend
npm start
```

The React dev server runs at `http://localhost:3000`. Docker serves the built dashboard at `http://localhost:5000`.

### Windows with Docker Desktop

```powershell
docker compose up --build
```

This starts Redis (published on `127.0.0.1:6380`, password-protected) and the dashboard (`127.0.0.1:5000`). Capture runs on the host, not in a container: in a second PowerShell window run

```powershell
.\start-capture.ps1
```

It requests Administrator access and connects host-side Scapy to the Docker Redis. Npcap must be installed; keep the capture window open. Only flows above the alert threshold appear in Threat Intel. A demo helper is also available at `scripts\5-demo-threat-capture.bat`.

### Verify the pipeline (synthetic)

```bash
cd backend
python verify_ensemble.py
```

Expected output:

```
RF predicted class=1 -> threat_name='DDoS' (P=1.0000)
ALERTS RAISED: 3
  src=45.0.0.1  severity=CRITICAL  threat=DDoS  score=1.000
```

This is a synthetic fusion/plumbing check. Its evidence is labelled `synthetic_fusion_verification` and must not be presented as live capture.

## Controlled live-lab capture

> Use only on an isolated network of systems you own: an attacker VM, a victim VM/service, and the sensor. Do not scan or flood public systems.

```powershell
# Terminal 1: Docker Redis + dashboard (http://localhost:5000)
docker compose up
```
```powershell
# Terminal 2: Administrator PowerShell, keep open.
# -LiveLab marks evidence as controlled live-lab traffic;
# -FeatureDump records the raw feature rows for later live-model training.
.\start-capture.ps1 -LiveLab -FeatureDump .\backend\evidence\live_lab_features.csv
```

Healthy capture logs include:

```
CAPTURE_HEARTBEAT alive
CAPTURE_HEALTH packets=... ipv4_tcp_udp=...
DIAGNOSTIC recon_error=... anomaly_score=...
```

Generate benign baseline traffic first, then only controlled scenarios against the isolated victim. Use the labelled feature dump and PCAP/event log to retrain into `models/live_flow_v1/` (planned; no live-trained model exists yet).

Before enabling AE-only alerting, validate score variation:

```powershell
cd backend
python validate_live_capture.py evidence\live_lab_features.csv --models models\live_flow_v1
```

Only after that passes, and after a live-lab threshold has been calibrated, may an operator enable the AE-only path on a later capture with `-EnableValidatedAeOnly` (sets `IDS_AE_ONLY_ALERTING_VALIDATED=true`). It is disabled by default.

Confirm alerts and evidence:

```powershell
docker compose exec redis redis-cli --no-auth-warning -a <REDIS_PASSWORD from .env> XLEN ids:alerts
Get-ChildItem .\backend\evidence | Sort-Object LastWriteTime -Descending | Select-Object -First 10
```

Evidence is written to `backend\evidence\alerts.jsonl` and `backend\evidence\threat-*.png`, each tagged with an origin: `synthetic_fusion_verification`, `live_lab`, or `live_unclassified`.

## Tests

```bash
cd backend
python -m pytest tests/ -v
```

Current result: **248 passed** (Windows 11, Python 3.11.9, 2026-10-01).

Coverage areas: preprocessing, sequence construction and leakage regression, live inference/fusion logic, CICFlowMeter reference-fixture feature parity, flow scoring, route security and auth, threat-intelligence privacy, whitelist behaviour, and AutoBlock command behaviour. Two dependency deprecation warnings (Scapy/cryptography) are expected.

## Live pipeline benchmark

`backend/benchmark_live_pipeline.py` — Windows, Python 3.11, CPU, CNN excluded (matching the live architecture), four-packet synthetic flows, batch size 1:

| Metric | Result |
|---|---|
| Final-packet → prediction latency | 98.15 ms median / 115.38 ms p95 / 121.41 ms p99 |
| Sustained throughput | 4.95 flows/s (19.81 packets/s for this workload) |
| Redis `XADD` latency | < 2.2 ms p99, zero errors |

These are workload-specific development measurements on **synthetic** flows: in-process processing latency only. They are not end-to-end capture → Redis → dashboard latency (not yet measured), not a NIC capacity claim, and not representative of arbitrary flow lengths, traffic mixes, or enterprise link speeds.

## Live detection status

Controlled LAN lab runs on 2026-10-01 (laptop sensor on Ethernet, a second device sending a sequential TCP connect+GET flood to a listener on the laptop; details in `PROGRESS.md`):

- After the train/serve fixes above, the system stays quiet on ordinary laptop traffic but does **not** alert on the flood (fused score about 0.47, below 0.85).
- The RF gave P(attack) above 0.5 on 0% of flood flows. The training "DDoS" class is slow LOIC-style flows (median 1.88 s, ~11.6 KB replies); the lab flood is fast and tiny (~6 ms, 59 bytes). Flows shaped like the training attack reached only 0.23–0.25.
- Earlier lab "detections" were an artefact of flag-count skew, since fixed.

So the live path works, but live detection quality is not demonstrated, and RF generalisation beyond the Friday DDoS capture is unproven. A 1-hour benign capture to measure the live false-alert rate is in progress.

## Redis and persistence

Redis Streams carry real-time alerts and a bounded dashboard history (`ids:alerts`, `MAXLEN ~5000`). The Docker configuration enables RDB persistence but not AOF, binds the published port to localhost only, and requires a password. Treat Redis as a live alert broker and short-term buffer, not a durable SIEM or evidence store.

## Automated blocking

Optional automated IP blocking is restricted to CRITICAL alerts and gated by whitelist, direction, TCP/SYN, local-destination, and configuration checks. IDS-created Linux rules are tagged for ownership, and persistent state drives reconciliation/TTL cleanup. Firewall command execution is regression-tested with mocks only; production firewall-policy safety across environments has not been established. Keep high-privilege firewall access (`NET_ADMIN`) disabled unless explicitly required and reviewed.

## Security notice

An AbuseIPDB API key was previously committed to this repository and remains in Git history. It must be revoked and replaced. Put the replacement in `backend/.env` as `ABUSEIPDB_API_KEY=...`; the Settings page no longer submits or stores the key.

## Team

Completed as a Final Year Project (FYP-II) at the Institute of Computer Sciences & Information Technology, The University of Agriculture, Peshawar, supervised by Mr. Yasir Ahmed.

Team: Visal Sattar, Khayal Baz Khalil, Shayan Khan. Primary engineering, model development, and system architecture by Visal Sattar.
