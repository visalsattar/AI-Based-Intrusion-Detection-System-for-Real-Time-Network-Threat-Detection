---

# AI-Based Intrusion Detection System (IDS)

---
## Summary

An AI-powered Network Intrusion Detection System (IDS) that monitors live network traffic and automatically detects cyberattacks in real time using a combination of three machine learning models. It was built as a Final Year Project (FYP-II) for a computer science/software engineering degree.

**The Problem It Solves:**
Traditional network security relies on signature-based detection — a list of known attack patterns. If an attacker uses a new technique not in the list, it goes undetected. This system solves that by using AI to learn what normal traffic looks like and flag anything that deviates — including attacks that have never been seen before.

**Why It Is a Strong Project:**
* Three models combined — not just one neural network.
* Real dataset — 225,745 actual network flows, not toy data.
* Full stack — AI + backend + frontend + Docker + CI all working together.
* Honest reporting — limitations disclosed, not hidden.
* 20 automated tests — proves the code is reliable, not just demo-ready.
* Production-grade architecture — Redis Streams, WebSockets, Docker health checks.

---

## How It Works

```
Network Traffic
      │
      ▼
┌─────────────┐    ┌──────────────────┐    ┌─────────────────────────┐
│   Packet    │    │    Feature       │    │    AI Ensemble          │
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
Ensemble logic: Fused score = 0.5 × AE anomaly score + 0.5 × RF attack probability. Two override rules apply: if AE confidence exceeds 0.97, AE wins; if RF confidence exceeds 0.90, RF wins. An alert fires when the fused score exceeds 0.85.

---

## Setup Instructions

**Prerequisites**
* Python 3.11
* Node.js 20 LTS
* Redis (running locally on port 6379)
* Npcap (for live packet capture on Windows)

Install Dependencies
```bash
# Backend
cd backend
pip install -r requirements.txt

# Frontend
cd frontend
npm install
```

Running the System
1. Preprocess dataset (first time only)

```Bash
cd backend
python main.py --mode preprocess --dataset "data/Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv" --multiclass
```

2. Train models (first time only)
```
Bash
cd backend
python run_training.py
```
Use run_training.py not main.py --mode train — avoids a Windows joblib deadlock.

3. Evaluate model performance
```
Bash
cd backend
python src/model_evaluation.py data/preprocessed/CICIDS2017_cleaned.csv
```

4. Start the backend
```
Bash
cd backend
python main.py
```

5. Start the frontend
```
Bash
cd frontend
npm start
```
Dashboard at http://localhost:3000.

6. Verify the full pipeline
```
Bash
cd backend
python verify_ensemble.py
```
Expected:
```
      RF predicted class=1 -> threat_name='DDoS' (P=1.0000)
ALERTS RAISED: 3
  src=45.0.0.1  severity=CRITICAL  threat=DDoS  score=1.000
```

Running Tests
```Bash
cd backend
python -m pytest tests/ -v
```
20 tests — preprocessing, sequence construction (leakage regression), and live inference ensemble.

Docker Configuration
```Bash
docker compose up --build
```
