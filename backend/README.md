# AI-Based Intrusion Detection System (Hybrid Architecture)

A hybrid network intrusion detection system combining an unsupervised
Autoencoder with supervised Random Forest and CNN classifiers, trained
on the CICIDS2017 dataset.

## Status

This codebase was substantially debugged and corrected from an earlier
version that contained several real issues: a debugging hack that
force-labeled every live network flow as a CRITICAL alert regardless
of the model's actual prediction, a feature-extraction routine that
fed the model mostly zeros, a CNN trained on random noise instead of
real data, and a dashboard backend that silently served fabricated
alert data whenever Redis was unreachable. All of these were found,
fixed, and verified against real data and real model runs. See
`docs/CHANGES.md` for the full list, and Thesis Chapter 7/8 for the
verified real performance numbers.

**Current real, verified performance** (held-out test set, CICIDS2017
Friday DDoS capture):

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Autoencoder (unsupervised) | ~78% | ~55-60% | ~44-49% | ~0.50-0.53 |
| Random Forest (supervised) | 99.7% | 99.3% | 99.7% | 99.5% |
| CNN (supervised) | 99.9% | 99.7% | 99.9% | 99.8% |

The Autoencoder's weaker performance relative to the supervised models
is a genuine, explained finding (see Thesis Section 7.6), not a bug.

## Setup

```bash
pip install -r requirements.txt --break-system-packages
```

(Requires: tensorflow, scikit-learn, pandas, numpy, flask, flask-socketio,
flask-cors, redis, scapy, joblib, pytest)

## Running the pipeline

**1. Preprocess real CICIDS2017 data:**
```bash
python src/data_preprocessing.py data/CICIDS2017/<your-file>.csv
```

**2. Train all three models:**
```bash
python main.py --mode train
```
This builds real sliding-window sequences from the preprocessed data
(see `src/sequence_builder.py` for the methodology and an important
note about using row-order as a proxy for temporal order, since this
CICIDS2017 distribution has no Timestamp column), then trains the
Autoencoder, Random Forest, and CNN.

**3. Evaluate real metrics:**
```bash
python src/model_evaluation.py data/preprocessed/<your-cleaned-file>.csv
```
Writes `models/real_metrics.json` with real, traceable numbers.

**4. Run the live sniffer (requires a real machine with NIC access --
   cannot be run in a sandboxed/cloud dev environment):**
```bash
sudo python main.py --mode ids
```

**5. Run the dashboard backend:**
```bash
docker compose up --build
```
Visit `http://localhost:5000`. Add `?demo=true` to see a clearly
labeled demo alert without live traffic; without it, the dashboard
shows real Redis state honestly, including an explicit error if
Redis is unreachable (it will never silently substitute fake data).

## Known limitations (see Thesis Chapter 8.2 for full discussion)

- Live sniffer computes ~24 of the model's 78 expected features in
  real time (the rest are disclosed, not hidden, as zero-filled).
- Trained and evaluated on one day of CICIDS2017 (DDoS traffic only),
  not the full multi-day, multi-attack-type dataset.
- Automated test suites (`tests/`) are scaffolded with documented
  planned cases but not yet implemented; verification so far has been
  manual (documented in Thesis Chapter 7.3/7.4).
- Live end-to-end latency has not been formally benchmarked.

## Project structure

```
backend/
├── main.py                  # Entry point: preprocess / train / run IDS
├── src/
│   ├── data_preprocessing.py    # CICIDS2017 cleaning + MinMax scaling
│   ├── sequence_builder.py      # CNN sequence construction (see docstring
│   │                             #   for the leakage bug found & fixed here)
│   ├── ai_model_development.py  # Autoencoder / RF / CNN architectures
│   ├── model_evaluation.py      # Real metrics computation
│   ├── ids_pipeline.py          # Live Scapy sniffer + real-time scoring
│   └── backend.py               # Flask/Redis/SocketIO dashboard API
├── models/                  # Trained model files + real_metrics.json
├── data/                    # CICIDS2017 raw + preprocessed data
├── tests/                   # Scaffolded test suite (see file docstrings)
└── frontend/                # React dashboard
```
