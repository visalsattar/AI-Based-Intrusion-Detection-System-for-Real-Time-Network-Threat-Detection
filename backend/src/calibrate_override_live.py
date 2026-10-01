"""
Calibrate the live autoencoder override from a LIVE benign capture (IDS_DUMP_FEATURES csv).

Why: src/calibrate_override.py calibrates on the offline CICIDS test split, which is exactly the
distribution the live sensor does not reproduce. This script uses what the sensor really emits for
normal traffic, applies the same pre-scaling fixes the live pipeline applies, and measures the
false-alert rate on a held-out later part of the capture so the number is not self-graded.

Usage (from backend/):
    python src/calibrate_override_live.py evidence/benign_long.csv [more.csv ...] \
        [--exclude-ip 192.168.18.25] [--percentile 99.5] [--write]

Without --write it only prints. With --write it writes models/override_calibration.json
(ae_override only; rf_override is left to the pipeline default / existing file).
"""
import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))


def _ae_scores(frame, models_dir):
    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
    import tensorflow as tf
    from ids_pipeline import RealTimeIDSPipeline as P

    scaler = joblib.load(os.path.join(models_dir, "feature_scaler.pkl"))
    names = [str(n) for n in scaler.feature_names_in_]
    missing = [n for n in names if n not in frame.columns]
    if missing:
        raise SystemExit(f"capture is missing {len(missing)} scaler columns, e.g. {missing[:3]}")
    X = frame[names].astype(float).copy()
    for c in P.TRAINING_ZERO_FEATURES:
        if c in X:
            X[c] = 0.0
    for c in P.TRAINING_BINARY_FEATURES:
        if c in X:
            X[c] = (X[c] > 0).astype(float)
    Xs = scaler.transform(X)
    ae = tf.keras.models.load_model(os.path.join(models_dir, "autoencoder.h5"), compile=False)
    err = ((Xs - ae.predict(Xs, verbose=0)) ** 2).mean(axis=1)
    with open(os.path.join(models_dir, "real_metrics.json"), encoding="utf-8") as fh:
        thr = float(json.load(fh)["autoencoder"]["threshold"])
    return err / (err + thr), err, thr


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("captures", nargs="+")
    ap.add_argument("--models", default="models")
    ap.add_argument("--percentile", type=float, default=99.5)
    ap.add_argument("--exclude-ip", action="append", default=[])
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args(argv)

    frame = pd.concat([pd.read_csv(p) for p in args.captures], ignore_index=True)
    if args.exclude_ip:
        bad = frame["src_ip"].isin(args.exclude_ip) | frame["dst_ip"].isin(args.exclude_ip)
        print(f"Excluding {int(bad.sum())} rows that involve {args.exclude_ip}")
        frame = frame[~bad]
    frame = frame.sort_values("ts").reset_index(drop=True)
    if len(frame) < 200:
        raise SystemExit(f"Only {len(frame)} benign flows; capture at least ~1 hour of normal use first.")

    score, err, thr = _ae_scores(frame, args.models)
    half = len(frame) // 2
    cal, held = score[:half], score[half:]
    proposed = float(np.percentile(cal, args.percentile))
    print(f"flows={len(frame)} (calibration {half}, held-out {len(frame) - half}); recon threshold={thr:.6f}")
    print(f"current default override 0.97 -> {np.mean(held > 0.97):.1%} of held-out benign flows alert on the AE alone")
    print(f"P{args.percentile} of calibration-half benign ae_score = {proposed:.4f}")
    print(f"proposed ae_override {proposed:.4f} -> {np.mean(held > proposed):.1%} of held-out benign flows alert (calibration half: {np.mean(cal > proposed):.1%})")
    secs = max(float(frame['ts'].iloc[-1] - frame['ts'].iloc[half]), 1.0)
    print(f"held-out span {secs / 3600:.2f} h -> about {np.sum(held > proposed) / (secs / 3600):.1f} AE-only alerts per hour at the proposed level")
    if proposed >= 0.9999:
        print("WARNING: proposed override is ~1.0; the AE cannot be used alone on this traffic (override would never fire).")
    if args.write:
        out = os.path.join(args.models, "override_calibration.json")
        cur = {}
        if os.path.exists(out):
            with open(out, encoding="utf-8") as fh:
                cur = json.load(fh)
        cur["ae_override"] = round(proposed, 4)
        cur["ae_override_source"] = f"live benign capture, P{args.percentile}, {len(frame)} flows"
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, indent=2)
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
