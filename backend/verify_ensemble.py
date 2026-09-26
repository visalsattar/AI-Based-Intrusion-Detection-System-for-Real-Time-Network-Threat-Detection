"""
Plumbing check for the live pipeline (no packet-capture privileges needed).

WHAT THIS PROVES
    synthetic packets -> packet_callback -> flow tracking -> FIN/RST completion -> feature
    extraction -> scaler -> autoencoder (+ RF) -> score fusion -> alert -> Redis 'ids:alerts',
    with every finished flow scored exactly once and the alert cooldown holding.

WHAT THIS DOES NOT PROVE
    Detection quality. The synthetic flows' timing features are not representative (Flow Duration
    is wall-clock, IATs come from the packets' fake timestamps), and step [4] feeds a row the
    Random Forest was TRAINED on, under an invented IP. Model outputs are printed, never asserted.
    For real detection numbers, capture your own traffic with IDS_DUMP_FEATURES and run
    tools/skew_report.py.

Exit code: 0 = plumbing OK, 1 = plumbing broken, 2 = model artifacts missing.
Run from backend/:  python verify_ensemble.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from scapy.all import IP, TCP  # noqa: E402

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE, "models", "autoencoder.h5")
SCALER_PATH = os.path.join(BASE, "models", "feature_scaler.pkl")
STREAM = "ids:alerts"


# --------------------------------------------------------------------------- scenarios
# Scoring happens when a flow FINISHES (FIN / RST / packet cap / idle), so every scenario ends
# its flows the way real traffic does. Without that nothing would be scored at all.

def benign_flow(t0):
    """Normal short HTTPS exchange, closed with FIN."""
    c, s = "10.0.0.20", "93.184.216.34"
    pkts = [
        IP(src=c, dst=s) / TCP(sport=51000, dport=443, flags="S"),
        IP(src=s, dst=c) / TCP(sport=443, dport=51000, flags="SA"),
        IP(src=c, dst=s) / TCP(sport=51000, dport=443, flags="A") / ("x" * 200),
        IP(src=s, dst=c) / TCP(sport=443, dport=51000, flags="PA") / ("y" * 500),
        IP(src=c, dst=s) / TCP(sport=51000, dport=443, flags="FA"),
    ]
    for i, p in enumerate(pkts):
        p.time = t0 + i * 0.05
    return pkts


def portscan_flow(t0):
    """250 SYN probes from one host to one port each; the closed port answers RST-ACK, which is
    what ends each 2-packet flow. Should produce at most one alert per severity (cooldown)."""
    attacker, victim = "45.13.227.7", "10.0.0.50"
    pkts = []
    for i in range(250):
        sport = 40000 + i
        a = IP(src=attacker, dst=victim) / TCP(sport=sport, dport=80, flags="S")
        b = IP(src=victim, dst=attacker) / TCP(sport=80, dport=sport, flags="RA")
        a.time, b.time = t0 + i * 0.0002, t0 + i * 0.0002 + 0.00005
        pkts += [a, b]
    return pkts


def synflood_flow(t0):
    """One fixed 4-tuple carrying 400 rapid SYNs, then an RST."""
    attacker, victim = "185.220.101.9", "10.0.0.50"
    pkts = []
    for i in range(400):
        p = IP(src=attacker, dst=victim) / TCP(sport=55555, dport=80, flags="S")
        p.time = t0 + i * 0.00001
        pkts.append(p)
    r = IP(src=victim, dst=attacker) / TCP(sport=80, dport=55555, flags="RA")
    r.time = t0 + 400 * 0.00001
    pkts.append(r)
    return pkts


SCENARIOS = [  # (title, builder, flows the pipeline must score)
    ("benign HTTPS flow", benign_flow, 1),
    ("port scan (250 probes, each answered by RST)", portscan_flow, 250),
    ("SYN flood (one 401-packet flow)", synflood_flow, 1),
]


# --------------------------------------------------------------------------- helpers

class CountingAE:
    """Transparent wrapper: counts rows sent to predict() so 'scored exactly once' is checkable."""
    def __init__(self, inner):
        self._inner, self.rows = inner, 0

    def predict(self, x, *a, **k):
        self.rows += len(x)
        return self._inner.predict(x, *a, **k)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class Tee:
    """Forwards xadd to the real stream (if any) and keeps a local copy of every alert."""
    def __init__(self, real=None):
        self.real, self.captured = real, []

    def get(self, key):
        return None          # never let stored UI settings (e.g. autoBlock) influence this check

    def xadd(self, stream, mapping, **kw):
        self.captured.append(mapping["data"])
        if self.real is not None:
            self.real.xadd(stream, mapping, **kw)


def _fmt(a):
    return (f"    src={a['src_ip']:<15} {a['severity']:<8} threat={a.get('threat_type', '?'):<15} "
            f"score={a['anomaly_score']:.3f} (ae={a.get('ae_anomaly_score', float('nan')):.3f}, "
            f"rf={a.get('rf_attack_prob')}) via {a.get('detection_source')} "
            f"suppressed_since_last={a.get('suppressed_since_last', 0)}")


def run_scenarios(pipeline, tee, say=print):
    """Feeds every scenario through the real packet path. Returns (ok, per-scenario results)."""
    ae = pipeline.autoencoder = CountingAE(pipeline.autoencoder)
    # Pin behaviour: no Redis-stored settings, and the IPS can never touch the firewall here.
    pipeline._settings_cache, pipeline._settings_loaded_at = {"autoBlock": False}, time.time() + 10**9
    pipeline.redis_client = tee
    pipeline.evidence_origin = "synthetic_fusion_verification"
    ok, results, t0 = True, [], 1_700_000_000.0

    for n, (title, build, expected) in enumerate(SCENARIOS, 1):
        pipeline._last_alert.clear()
        rows_before, alerts_before = ae.rows, len(tee.captured)
        for p in build(t0 + n * 100):
            pipeline.packet_callback(p)
        pipeline.flush()
        scored = ae.rows - rows_before
        alerts = [json.loads(x) for x in tee.captured[alerts_before:]]
        good = scored == expected and (len(alerts) <= 3)
        ok &= good
        say(f"[{n}] {title}\n    flows scored: {scored} (expected {expected})  alerts: {len(alerts)}  "
            f"-> {'plumbing OK' if good else 'PLUMBING PROBLEM'}")
        for a in alerts:
            say(_fmt(a))
        results.append({"title": title, "scored": scored, "expected": expected, "alerts": alerts})

    leftover = len(pipeline.flow_tracker)
    if leftover:
        ok = False
        say(f"    PLUMBING PROBLEM: {leftover} finished flows were never scored/removed")
    return ok, results


def training_row_smoke_test(pipeline, say=print):
    """
    [4] NAMING/PLUMBING CHECK ONLY. The first attack row of the training CSV is inside the split
    the RF trained on, so P(attack)=1.0 here says nothing about generalisation.
    """
    csv_path = os.path.join(BASE, "data", "preprocessed", "CICIDS2017_cleaned.csv")
    if pipeline.random_forest is None or not os.path.exists(csv_path):
        say("[4] skipped (needs the RF and data/preprocessed/CICIDS2017_cleaned.csv)")
        return
    import numpy as np
    import pandas as pd
    from datetime import datetime

    row = pd.read_csv(csv_path)
    row = row[row["Label"] == 1].iloc[0].drop("Label").values.astype(np.float32).reshape(1, -1)
    # The CSV is already MinMax-scaled: do NOT run feature_scaler.transform on it.
    cls = int(pipeline.random_forest.predict(row)[0])
    prob = float(pipeline.random_forest.predict_proba(row)[0, pipeline._rf_attack_idx])
    name = pipeline._label_map.get(cls, f"Class {cls}")
    err = float(np.mean(np.square(row - pipeline.autoencoder.predict(row, verbose=0))))
    say(f"[4] training-row smoke test: RF class={cls} -> '{name}' (P={prob:.4f}), AE error={err:.6f}"
        "\n    (a TRAINING row under an invented IP -- proves naming plumbing, not detection)")
    fk, now = (("198.51.100.7", 12345), ("10.0.0.1", 80), 6), datetime.now()
    pipeline._last_alert.clear()
    pipeline.flow_tracker[fk] = {
        "packets": 10, "bytes": 400, "first_seen": now, "last_seen": now, "protocol": 6,
        "packet_list": [], "init_src": "198.51.100.7", "init_sport": 12345,
        "init_dst": "10.0.0.1", "init_dport": 80, "fwd_win": 0, "bwd_win": 0, "done": False,
        "init_syn": False,          # unproven direction: the IPS refuses to act on it
    }
    pipeline._process_prediction(fk, err, prob, name)
    pipeline.flow_tracker.pop(fk, None)


def main():
    # Evidence emitted by this script is constructed plumbing-test output, not
    # a network capture.  The evidence card and JSONL record carry this label.
    # The verifier intentionally exercises AE-only fusion branches.  This is
    # safe here because its evidence is explicitly synthetic.
    os.environ["IDS_AE_ONLY_ALERTING_VALIDATED"] = "true"
    if not (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)):
        print("Model artifacts missing (backend/models/autoencoder.h5, feature_scaler.pkl). "
              "Download them from the release or train first.")
        return 2

    from ids_pipeline import RealTimeIDSPipeline
    from redis_util import make_redis

    pipeline = RealTimeIDSPipeline(
        model_path=MODEL_PATH, feature_extractor_path=SCALER_PATH,
        alert_threshold=0.85,             # same as run_ids_capture()
        packet_batch_size=10**9, batch_interval=10**9,   # we flush manually
    )
    real = None
    try:
        real = make_redis()
        real.ping()
    except Exception as e:
        print(f"Redis unavailable ({e}); using an in-memory capture instead (no read-back check).")
        real = None

    print("=" * 72)
    print(f"Ensemble: {'autoencoder + random forest' if pipeline.random_forest is not None else 'AUTOENCODER ONLY (RF not loaded)'}"
          f" | recon threshold {pipeline.recon_threshold:.7f} (calibrated={pipeline._threshold_calibrated})")
    print("=" * 72)

    tee = Tee(real)
    ok, _ = run_scenarios(pipeline, tee)
    training_row_smoke_test(pipeline)

    if real is not None and tee.captured:
        try:
            stored = {f["data"] for _, f in real.xrevrange(STREAM, count=len(tee.captured) + 50)}
            missing = [d for d in tee.captured if d not in stored]
            print(f"\nRedis read-back: {len(tee.captured) - len(missing)}/{len(tee.captured)} alerts found in '{STREAM}'")
            ok &= not missing
        except Exception as e:
            print(f"\nRedis read-back failed: {e}")
            ok = False

    print("\nPLUMBING CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
