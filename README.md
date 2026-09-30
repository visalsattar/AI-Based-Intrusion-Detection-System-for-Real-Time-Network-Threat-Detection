AI-Based Intrusion Detection System (IDS)

Final Year Project — BS Computer Science, The University of Agriculture, Peshawar

Summary

An AI-powered Network Intrusion Detection System (IDS) that monitors live network traffic and detects cyberattacks in real time using a fused Random Forest + Autoencoder pipeline. A third model — a CNN — was trained and evaluated offline for architecture comparison, but is not part of the live detection path (see Why the CNN doesn't run live, below).

The Problem It Solves:
Traditional network security relies on signature-based detection — a list of known attack patterns. If an attacker uses a new technique not in the list, it goes undetected. This system learns what normal traffic looks like and flags anything that deviates, including attacks that have never been seen before.

Why It Is a Strong Project:

Two models fused for live detection, with a third (CNN) built and benchmarked offline to compare architectures

Real dataset — 225,745 actual network flows (CICIDS2017), not toy data

Full stack — AI + backend + frontend + Docker integration, with automated regression tests

Honest reporting — the Autoencoder's weaker standalone performance is disclosed, not hidden

Automated tests cover preprocessing, flow scoring, route security, threat-intel privacy, and train/test leakage

Redis Streams, WebSockets, and Docker health checks for the live pipeline

How It Works

Network Traffic
      │
      ▼
┌─────────────┐    ┌──────────────────┐    ┌─────────────────────────┐
│   Packet    │    │    Feature       │    │    Live Fusion          │
│   Capture   │───▶│    Extraction    │───▶│                         │
│   (Scapy)   │    │  (78 CICIDS2017  │    │  Autoencoder (AE)       │
└─────────────┘    │    features)     │    │  + Random Forest (RF)   │
                    └──────────────────┘    │                         │
                                            │  score = 0.5×AE + 0.5×RF│
                                            └────────────┬────────────┘
                                                         │
                                                         ▼
                                            ┌─────────────────────────┐
                                            │    Alert Engine         │
                                            │  (Redis ids:alerts)     │
                                            └────────────┬────────────┘
                                                         │
                                                         ▼
                                            ┌─────────────────────────┐
                                            │    React Dashboard      │
                                            │  (Flask + Socket.IO)    │
                                            └─────────────────────────┘

Fusion logic: score = 0.5 × AE anomaly score + 0.5 × RF attack probability. Two override rules apply: if AE confidence exceeds 0.97, AE wins outright; if RF confidence exceeds 0.90, RF wins outright. An alert fires when the fused score exceeds 0.85.

Why the CNN doesn't run live: the CNN classifies over sequences of 100 consecutive flows, which only has meaning on the row-ordered CICIDS2017 CSV used for offline evaluation. Live per-flow capture provides no equivalent temporal window, so running the CNN live would feed it out-of-distribution input. It was trained, benchmarked, and documented, then intentionally excluded from the live path rather than shipped in a way that would silently misbehave in production.

Model Performance

The project's held-out DDoS/benign flow-level evaluation reports:

Model / path

Accuracy

Precision

Recall

F1

Role

Random Forest

99.75%

99.26%

99.74%

99.50%

Live fusion

Autoencoder

78.87%

59.78%

48.88%

53.78%

Live fusion

RF + AE fusion

99.60%

98.90%

99.51%

99.20%

Live decision path

CNN

99.76%

99.12%

99.91%

99.51%

Offline only

The RF/AE/fusion results use the project's 45,149-row held-out flow-level test split. The CNN result uses a separate 4,505-sequence evaluation subset built with 100-row windows and stride 10. These are experiment-specific results, not guarantees of live-network accuracy.

The live fusion path was validated on the held-out DDoS/benign split, but this is not independent cross-dataset validation or evidence for all CICIDS2017 attack families. The live extractor now produces the complete 78-feature input contract; exact numerical equivalence with the specific CICFlowMeter Java build/export configuration that generated the training CSV has not been established.

Setup Instructions

Prerequisites

Python 3.11

Node.js 20 LTS

Redis (running locally on port 6379)

Npcap (for live packet capture on Windows)

Dataset: This repo does not include the CICIDS2017 dataset (too large for GitHub). Download Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv from the official CIC dataset page and place it in backend/data/CICIDS2017/ if you plan to preprocess or retrain.

Install dependencies

# Backend
cd backend
pip install -r requirements.txt

# Frontend
cd frontend
npm install

Option A — Use the pre-trained models (fastest)

Download autoencoder.h5, random_forest.pkl, cnn_classifier.h5, feature_scaler.pkl, and label_map.json from the repository Releases page (create this release before first use) and place them in backend/models/. Then skip to Running the system below.

Option B — Train from scratch

cd backend

# 1. Preprocess dataset (first time only)
python main.py --mode preprocess --dataset "data/CICIDS2017/Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv" --multiclass

# 2. Train models
python run_training.py
# Use run_training.py, not main.py --mode train — avoids a Windows joblib deadlock.

# 3. Evaluate model performance
python src/model_evaluation.py data/preprocessed/CICIDS2017_cleaned.csv

Running the system

# Start the backend
cd backend
python main.py

# Start the frontend (separate terminal)
cd frontend
npm start

Dashboard available at localhost:3000 for React development (Docker serves it at localhost:5000).

Live capture on Windows with Docker Desktop

Start Redis and the dashboard with docker compose up --build. In another PowerShell window run ./start-capture.ps1; it requests Administrator access and connects host-side Scapy to Docker Redis. Npcap must be installed. Keep the capture window open. Only flows above the alert threshold appear in Threat Intel.

Controlled live-lab capture and thesis evidence

Use this only on an isolated network containing systems you own: an attacker VM,
a victim VM/service, and the sensor. verify_ensemble.py remains a synthetic
fusion/plumbing check; its evidence is marked as synthetic and must not be
presented as a live capture.

# Terminal 1: start Docker Redis + dashboard
cd AI-Based-Intrusion-Detection-System-for-Real-Time-Network-Threat-Detection
docker compose up

Open the dashboard at http://localhost:5000.

# Terminal 2: Administrator PowerShell, keep this open.
# -LiveLab marks evidence as controlled live-lab traffic; -FeatureDump records
# the exact raw rows that must later be used for live-model training.
cd AI-Based-Intrusion-Detection-System-for-Real-Time-Network-Threat-Detection
.\start-capture.ps1 -LiveLab -FeatureDump .\backend\evidence\live_lab_features.csv

Healthy capture logs include:

CAPTURE_HEARTBEAT alive
CAPTURE_HEALTH packets=... ipv4_tcp_udp=...
DIAGNOSTIC recon_error=... anomaly_score=...

Generate benign baseline traffic first, then only controlled scenarios against
the isolated victim. Do not scan or flood public systems. Use the labelled
feature dump and PCAP/event log to retrain into models/live_flow_v1/.

Before enabling AE-only alerting, validate score variation:

cd backend
python validate_live_capture.py evidence\live_lab_features.csv --models models\live_flow_v1

Only after that command passes, an operator may explicitly enable the
AE-only path on a later capture with -EnableValidatedAeOnly. The default
remains disabled.

Confirm alerts and evidence:

docker compose exec redis redis-cli XLEN ids:alerts
Get-ChildItem .\backend\evidence | Sort-Object LastWriteTime -Descending | Select-Object -First 10

Evidence is saved in backend\evidence\alerts.jsonl and backend\evidence\threat-*.png with an explicit origin (synthetic_fusion_verification, live_lab, or live_unclassified). Do not set IDS_AE_ONLY_ALERTING_VALIDATED=true until the validator passes and you have calibrated a live-lab model threshold.

You can also start the demo helper from bat files\5-demo-threat-capture.bat.

The AbuseIPDB credential previously committed to GitHub must be revoked and replaced. Put the replacement in backend/.env as ABUSEIPDB_API_KEY=... . The Settings page no longer submits or stores the key. Removing it from current files does not remove it from old Git commits.

Verify the full pipeline

cd backend
python verify_ensemble.py

Expected output:

RF predicted class=1 -> threat_name='DDoS' (P=1.0000)
ALERTS RAISED: 3
  src=45.0.0.1  severity=CRITICAL  threat=DDoS  score=1.000

Run tests

cd backend
python -m pytest tests/ -v

The current suite contains 98 collected pytest items. The latest verified run passed all 98 items with 0 failures/errors. Two dependency deprecation warnings from Scapy/cryptography remain. Coverage includes preprocessing, sequence construction and leakage regression, live inference/fusion logic, flow scoring, route security, threat-intelligence privacy, whitelist behavior, and AutoBlock command behavior.

Live Pipeline Benchmark

A controlled Windows/Python 3.11 CPU benchmark was run with the CNN excluded, matching the actual live architecture. For four-packet synthetic flows and batch size 1, the pipeline measured 98.15 ms median, 115.38 ms p95, and 121.41 ms p99 final-packet-to-prediction-processing latency. Sustained workload throughput was 4.95 completed flows/s, equivalent to 19.81 packets/s for this fixed four-packet synthetic workload. Redis XADD latency remained below 2.2 ms at p99 with zero Redis errors.

These are workload-specific development measurements, not a maximum NIC capacity claim and not a benchmark for arbitrary packet sizes, flow lengths, traffic distributions, or enterprise-scale link speeds.

Redis and Persistence

Redis Streams provide the real-time alert transport and bounded dashboard history. The audited deployment uses Redis RDB persistence but does not enable AOF, and the alert stream is bounded (MAXLEN ~5000). The published Redis port is localhost-only in the audited Docker configuration and authentication is enabled. Redis should therefore be treated as the live alert broker and short-term/bounded alert buffer, not as a dedicated durable SIEM or evidence database.

Automated Blocking

Optional automated IP blocking is restricted to CRITICAL alerts and guarded by whitelist, direction, TCP/SYN, local-destination, and configuration checks. Linux IDS-created rules are tagged for ownership and persistent state is used for reconciliation/TTL cleanup. Firewall command execution is regression-tested with mocks; comprehensive production firewall-policy safety across deployment environments has not been established. The default deployment should keep high-privilege firewall access disabled unless explicitly required and reviewed.

Docker

docker compose up --build

Team

Completed as a Final Year Project (FYP-II) at the Institute of Computer Sciences & Information Technology, The University of Agriculture, Peshawar, supervised by Mr. Yasir Ahmed. Team: Visal Sattar, Khayal Baz Khalil, Shayan Khan. Primary engineering, model development, and system architecture by Visal Sattar.