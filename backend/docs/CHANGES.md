# Changes Made During This Development Cycle

This document lists every substantive bug found and fixed, and what
was verified versus what remains a disclosed limitation. Written for
both future development and Viva/examiner reference.

## Fixed and verified (re-ran the actual code, observed real output)

### 1. `data_preprocessing.py` — double-scaling bug
`normalize_features(fit=True)` was called twice in sequence, scaling
already-scaled data a second time. Fixed to call once. Also switched
`StandardScaler` → `MinMaxScaler` to match the thesis's documented
methodology (Chapter 5.4), and fixed the resulting attribute references
(`mean_`/`scale_` → `data_min_`/`data_max_`).
**Verified:** ran against the full real 225,745-row CICIDS2017 file;
confirmed output range is correctly [0.0, 1.0], no NaN/Inf rows remain,
no leakage columns present.

### 2. `ai_model_development.py` / `main.py` — CNN trained on random noise
The original `train_models()` generated CNN training sequences with
`np.random.randn(...)` — pure Gaussian noise, never connected to real
traffic data. Any reported CNN metrics from before this fix describe a
model that learned to classify noise, not network behavior.
**Fixed:** built `sequence_builder.py`, which constructs real sliding-
window sequences from the actual preprocessed data, using row order as
a documented proxy for temporal order (this CICIDS2017 distribution has
no Timestamp column — see that file's docstring for the full rationale).
**Verified:** ran full training on real data; CNN achieved 99.91%
accuracy on a genuinely held-out test set (independently re-verified,
not just trusted from Keras's training-time output).

### 3. Train/test leakage in sequence construction (found during fixing #2)
A second, independently-discovered sequence-building approach (building
all overlapping windows first, then randomly splitting them) was found
elsewhere in the codebase. Testing showed adjacent windows at
window_size=100/stride=10 share 90% of their rows — meaning this
approach would leak ~90%-overlapping windows across the train/test
boundary. **This approach was rejected.** The correct approach (used in
`sequence_builder.py`) splits flat data into train/val/test FIRST,
preserving row order, then builds windows independently within each
split — guaranteeing zero row-overlap across splits.
**Verified:** automated self-test in `sequence_builder.py` (`python
src/sequence_builder.py`) confirms zero overlap; all tests pass.

### 4. `ids_pipeline.py` — the "if True:" hack
`_process_prediction()` contained `if True:` immediately followed by a
hardcoded `fake_score = 0.98` and `severity = 'CRITICAL'`, completely
ignoring the model's real anomaly_score. Every processed flow was
unconditionally reported as a CRITICAL alert. This was a debugging
shortcut (per its own comment, "THE MAGIC HACK") never reverted.
**Fixed:** removed the hack; severity is now derived from the real
anomaly_score via the (previously unused) `_compute_severity()`
function, gated by the real `alert_threshold`.
**Verified:** syntax-checked, imports cleanly, logic-tested with
constructed Scapy packet objects (could not test with a real NIC —
no sandbox network interface available; this requires testing on real
hardware, see "Not independently verified" below).

### 5. `ids_pipeline.py` — feature extraction was 87% zero-padded
`_extract_flow_features()` computed only 10 real values out of the 78
the model expects, padding the remaining 68 with zeros. Feeding the
model mostly-zero input produces unreliable predictions, which is the
most likely explanation for live testing never producing a detection.
**Fixed:** now computes ~24 real statistics (packet size mean/std/min/
max, inter-arrival-time mean/std/min/max, TCP flag counts, byte/packet
rates) directly from real Scapy packet objects in the flow.
**Verified:** logic-tested against deliberately constructed Scapy
packets with known properties; output values matched hand-calculated
expected results exactly. Full 78-feature parity with CICFlowMeter is
NOT achieved — this is disclosed as a limitation, not hidden.

### 6. `ids_pipeline.py` — alert_threshold was set to 0.0
Found commented out: `#alert_threshold: float = 0.85` with the active
line set to `0.0`, meaning every flow with any anomaly score above zero
would pass the gate. Restored 0.85 as the real default.

### 7. `backend.py` — silent mock-data fallback
`/api/dashboard` served a hardcoded fake alert (with a fixed 0.92 score
and a 2024-01-15 timestamp) whenever `redis_client is None`, and a bare
`except:` swallowed any Redis read error and substituted the same mock
data with no logging. This meant a genuine Redis outage looked
identical to "system working, no threats found."
**Fixed:** mock data now only appears via explicit opt-in (`?demo=true`
query param or `DEMO_MODE` env var), clearly labeled `is_demo: true` and
`[DEMO DATA - NOT A REAL DETECTION]`. A genuine Redis outage now returns
HTTP 503 with an honest error message and `data_source: "ERROR"`.
**Verified:** ran a real local Redis instance, tested all three
real scenarios (empty/live, demo, and genuinely-down) via Flask's test
client; confirmed each returns the correct, distinguishable response.

### 8. Autoencoder architecture: tested sigmoid vs linear output activation
Hypothesis: since inputs are MinMax-scaled to [0,1], a bounded sigmoid
output should reconstruct better than the original unbounded linear
output. **Tested directly:** retrained with sigmoid, got ROC-AUC 0.688
vs. linear's 0.772. **Linear was kept** because it measurably performed
better — this is reported as a negative result, not silently discarded.

## Found but NOT fixed (disclosed as limitations — see Thesis Ch 8.2)

- Live sniffer's feature set (~24 of 78) is real but incomplete.
- Only one day of CICIDS2017 (Friday DDoS) was used for training/eval;
  the full multi-day, multi-attack-type dataset was not.
- `tests/test_*.py` are scaffolded with documented planned cases, not
  implemented as automated pytest suites.
- Live end-to-end latency (Scapy capture → React render) was never
  formally measured; the original thesis's "45–85ms" figure was found
  to have no actual measurement behind it and was removed rather than
  kept as an unverifiable claim.
- The live pipeline (`ids_pipeline.py`'s `sniff()` call) could not be
  tested end-to-end in this development environment, which has no real
  network interface. Everything testable without a NIC was verified;
  running it on real hardware and confirming it produces real alerts
  from real traffic remains the responsibility of whoever runs it next.

## Real, verified final metrics

See `models/real_metrics.json` for the machine-readable version, and
Thesis Chapter 7 Table 7.1 / Section 7.6 for the full discussion of
why the supervised models (RF, CNN) substantially outperform the
unsupervised Autoencoder on this dataset.
