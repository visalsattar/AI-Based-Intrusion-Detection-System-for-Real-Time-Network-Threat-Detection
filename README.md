# AI-Based Intrusion Detection System (IDS)

Final Year Project — BS Computer Science, The University of Agriculture, Peshawar

---

## Summary

An AI-powered Network Intrusion Detection System (IDS) that monitors live network traffic and detects cyberattacks in real time using a fused Random Forest + Autoencoder pipeline. A third model — a CNN — was trained and evaluated offline for architecture comparison, but is not part of the live detection path (see *Why the CNN doesn't run live*, below).

**The Problem It Solves:**
Traditional network security relies on signature-based detection — a list of known attack patterns. If an attacker uses a new technique not in the list, it goes undetected. This system learns what normal traffic looks like and flags anything that deviates, including attacks that have never been seen before.

**Why It Is a Strong Project:**
- Two models fused for live detection, with a third (CNN) built and benchmarked offline to compare architectures
- Real dataset — 225,745 actual network flows (CICIDS2017), not toy data
- Full stack — AI + backend + frontend + Docker + CI all working together
- Honest reporting — the Autoencoder's weaker standalone performance is disclosed, not hidden
- 20 automated tests, including a regression test for train/test leakage
- Redis Streams, WebSockets, and Docker health checks for the live pipeline

---

## How It Works

```
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
```

**Fusion logic:** `score = 0.5 × AE anomaly score + 0.5 × RF attack probability`. Two override rules apply: if AE confidence exceeds 0.97, AE wins outright; if RF confidence exceeds 0.90, RF wins outright. An alert fires when the fused score exceeds 0.85.

**Why the CNN doesn't run live:** the CNN classifies over sequences of 100 consecutive flows, which only has meaning on the row-ordered CICIDS2017 CSV used for offline evaluation. Live per-flow capture provides no equivalent temporal window, so running the CNN live would feed it out-of-distribution input. It was trained, benchmarked, and documented, then intentionally excluded from the live path rather than shipped in a way that would silently misbehave in production.

---

## Model Performance (held-out test set)

| Model | F1-Score | Role |
|---|---|---|
| Random Forest | ~99.5% | Live fusion |
| Autoencoder | ~52-54%* | Live fusion |
| CNN | ~99.5% | Offline only |

*The Autoencoder's lower standalone score reflects the inherent difficulty of unsupervised anomaly detection on this dataset — it's reported here rather than omitted, and is why the fusion layer weights it alongside a supervised model instead of relying on it alone.

---

## Setup Instructions

**Prerequisites**
- Python 3.11
- Node.js 20 LTS
- Redis (running locally on port 6379)
- Npcap (for live packet capture on Windows)

**Dataset:** This repo does not include the CICIDS2017 dataset (too large for GitHub). Download `Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv` from the [official CIC dataset page](https://www.unb.ca/cic/datasets/ids-2017.html) and place it in `backend/data/CICIDS2017/` if you plan to preprocess or retrain.

**Install dependencies**
```bash
# Backend
cd backend
pip install -r requirements.txt

# Frontend
cd frontend
npm install
```

**Option A — Use the pre-trained models (fastest)**

Download `autoencoder.h5`, `random_forest.pkl`, `cnn_classifier.h5`, `feature_scaler.pkl`, and `label_map.json` from the [Releases page](https://github.com/visalsattar/AI-Based-Intrusion-Detection-System-for-Real-Time-Network-Threat-Detection/releases) and place them in `backend/models/`. Then skip to *Running the system* below.

**Option B — Train from scratch**
```bash
cd backend

# 1. Preprocess dataset (first time only)
python main.py --mode preprocess --dataset "data/CICIDS2017/Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv" --multiclass

# 2. Train models
python run_training.py
# Use run_training.py, not main.py --mode train — avoids a Windows joblib deadlock.

# 3. Evaluate model performance
python src/model_evaluation.py data/preprocessed/CICIDS2017_cleaned.csv
```

**Running the system**
```bash
# Start the backend
cd backend
python main.py

# Start the frontend (separate terminal)
cd frontend
npm start
```
Dashboard available at `http://localhost:3000`.

**Verify the full pipeline**
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

**Run tests**
```bash
cd backend
python -m pytest tests/ -v
```
20 tests covering preprocessing, sequence construction (including a train/test leakage regression), and live inference fusion logic.

**Docker**
```bash
docker compose up --build
```

---

## Team

Completed as a Final Year Project (FYP-II) at the Institute of Computer Sciences & Information Technology, The University of Agriculture, Peshawar, supervised by Mr. Yasir Ahmed. Team: Visal Sattar, Khayal Baz Khalil, Shayan Khan. Primary engineering, model development, and system architecture by Visal Sattar.
