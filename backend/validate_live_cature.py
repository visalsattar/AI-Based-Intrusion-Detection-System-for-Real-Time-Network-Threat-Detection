"""Validate score variation for a controlled live-lab feature capture.

Run after recording a labelled session with IDS_DUMP_FEATURES.  This does not
claim detection quality: it only prevents enabling AE-only alerting when the
live model emits effectively one constant score.

Example:
    python validate_live_capture.py evidence/live_lab/features.csv \
        --models models/live_flow_v1
"""
import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
from joblib import load


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_csv")
    parser.add_argument("--models", default="models/live_flow_v1")
    parser.add_argument("--min-rows", type=int, default=30)
    parser.add_argument("--min-score-std", type=float, default=1e-4)
    args = parser.parse_args(argv)

    import tensorflow as tf
    scaler = load(os.path.join(args.models, "feature_scaler.pkl"))
    model = tf.keras.models.load_model(os.path.join(args.models, "autoencoder.h5"), compile=False)
    metrics_path = os.path.join(args.models, "real_metrics.json")
    with open(metrics_path, encoding="utf-8") as fh:
        threshold = float(json.load(fh)["autoencoder"]["threshold"])

    frame = pd.read_csv(args.capture_csv)
    names = list(scaler.feature_names_in_)
    missing = [name for name in names if name not in frame]
    if missing:
        print(f"FAIL: capture is missing {len(missing)} deployed feature columns: {missing[:3]}")
        return 2
    if len(frame) < args.min_rows:
        print(f"FAIL: need at least {args.min_rows} finished flows; found {len(frame)}")
        return 2
    x = scaler.transform(frame[names])
    error = np.mean(np.square(x - model.predict(x, verbose=0)), axis=1)
    score = error / (error + threshold)
    unique = len(np.unique(np.round(score, 8)))
    std = float(np.std(score))
    report = {"rows": len(frame), "score_std": std, "unique_scores_8dp": unique,
              "score_p05": float(np.percentile(score, 5)), "score_p50": float(np.percentile(score, 50)),
              "score_p95": float(np.percentile(score, 95)), "min_score_std": args.min_score_std}
    print(json.dumps(report, indent=2))
    if unique < 2 or std < args.min_score_std:
        print("FAIL: scores are effectively constant. Do not enable AE-only alerting.")
        return 1
    print("PASS: scores vary. This is only a prerequisite; calibrate on labelled held-out live-lab data next.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
