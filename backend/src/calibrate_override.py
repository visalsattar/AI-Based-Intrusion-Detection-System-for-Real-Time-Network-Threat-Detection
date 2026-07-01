"""
Calibrate the confidence-override thresholds (AE_OVERRIDE_CONF /
RF_OVERRIDE_CONF) used by ids_pipeline.RealTimeIDSPipeline from REAL benign
traffic — instead of the hand-picked 0.97 / 0.90 defaults.

Rationale (state this in the thesis): the override lets a single highly-
confident model raise an alert on its own. To keep that from false-alarming
on normal traffic, each override threshold should sit just above where benign
flows score. This mirrors exactly how the reconstruction threshold in
real_metrics.json is derived from benign data — same methodology, applied to
the fused-ensemble override.

Method:
  * Rebuild the SAME train/test split model_evaluation.py uses (no leakage).
  * On BENIGN test rows only, compute:
      - ae_score  = e / (e + recon_threshold)     (autoencoder side)
      - rf_prob   = P(attack) from the random forest (supervised side)
  * Set each override to a high percentile of the benign distribution, so at
    most (100 - percentile)% of benign flows can self-trigger that override.
  * Report the ATTACK recall each threshold would achieve, so the
    precision/recall trade-off is explicit, not hidden.

Writes models/override_calibration.json, which the pipeline loads at startup
(falling back to the coded defaults when the file is absent).

Usage:
    python src/calibrate_override.py [path_to_preprocessed_csv] \
        [--ae-percentile 99.5] [--rf-percentile 99.5]
"""
import argparse
import json
import os
import sys

import numpy as np
import joblib
import tensorflow as tf

sys.path.insert(0, os.path.dirname(__file__))
from sequence_builder import build_cnn_sequences  # noqa: E402


def _recon_threshold(models_dir):
    """Read the calibrated reconstruction threshold the live pipeline uses."""
    path = os.path.join(models_dir, "real_metrics.json")
    with open(path) as f:
        thr = json.load(f).get("autoencoder", {}).get("threshold")
    if not thr:
        raise SystemExit(
            f"No autoencoder threshold in {path}. Run model_evaluation.py first."
        )
    return float(thr)


def calibrate(csv_path, models_dir="models", ae_pct=99.5, rf_pct=99.5,
              output="models/override_calibration.json"):
    recon_threshold = _recon_threshold(models_dir)
    print(f"Using reconstruction threshold {recon_threshold:.7f} from real_metrics.json")

    data = build_cnn_sequences(csv_path, window_size=100, stride=10)
    X_test, y_test = data["X_test_flat"], data["y_test_flat"]
    benign = X_test[y_test == 0]
    attack = X_test[y_test == 1]
    print(f"Held-out test: {len(benign)} benign, {len(attack)} attack rows")
    if len(benign) == 0:
        raise SystemExit("No benign rows in the test split — cannot calibrate.")

    # ---- Autoencoder side ------------------------------------------------
    ae = tf.keras.models.load_model(os.path.join(models_dir, "autoencoder.h5"), compile=False)

    def ae_scores(X):
        err = np.mean(np.square(X - ae.predict(X, verbose=0)), axis=1)
        return err / (err + recon_threshold)

    benign_ae = ae_scores(benign)
    ae_override = float(np.percentile(benign_ae, ae_pct))
    ae_recall = float((ae_scores(attack) > ae_override).mean()) if len(attack) else float("nan")
    print("\n[Autoencoder override]")
    print(f"  benign ae_score percentiles: "
          f"p90={np.percentile(benign_ae,90):.4f} p99={np.percentile(benign_ae,99):.4f} "
          f"p{ae_pct}={ae_override:.4f}")
    print(f"  -> AE_OVERRIDE_CONF = {ae_override:.4f} "
          f"(self-triggers on ~{100-ae_pct:.1f}% of benign; catches "
          f"{ae_recall*100:.1f}% of attacks on the AE signal alone)")

    # ---- Random forest side ---------------------------------------------
    rf_override = None
    rf_path = os.path.join(models_dir, "random_forest.pkl")
    if os.path.exists(rf_path):
        rf = joblib.load(rf_path)
        attack_idx = list(rf.classes_).index(1) if 1 in rf.classes_ else -1
        benign_rf = rf.predict_proba(benign)[:, attack_idx]
        rf_override = float(np.percentile(benign_rf, rf_pct))
        rf_recall = (float((rf.predict_proba(attack)[:, attack_idx] > rf_override).mean())
                     if len(attack) else float("nan"))
        print("\n[Random forest override]")
        print(f"  benign P(attack) percentiles: "
              f"p90={np.percentile(benign_rf,90):.4f} p99={np.percentile(benign_rf,99):.4f} "
              f"p{rf_pct}={rf_override:.4f}")
        print(f"  -> RF_OVERRIDE_CONF = {rf_override:.4f} "
              f"(self-triggers on ~{100-rf_pct:.1f}% of benign; catches "
              f"{rf_recall*100:.1f}% of attacks on the RF signal alone)")

    result = {
        "methodology": (
            "Override thresholds set to a high percentile of benign-only "
            "scores on the held-out test split, so at most (100-percentile)% "
            "of benign flows can self-trigger an override."
        ),
        "recon_threshold": recon_threshold,
        "ae_override": ae_override,
        "ae_percentile": ae_pct,
        "rf_override": rf_override,
        "rf_percentile": rf_pct if rf_override is not None else None,
    }
    with open(output, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nWrote {output} — the pipeline will load these at startup.")
    print("(Delete that file to revert to the coded 0.97 / 0.90 defaults.)")
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?",
                    default="data/preprocessed/CICIDS2017_cleaned.csv",
                    help="Preprocessed CICIDS CSV (same one used for training).")
    ap.add_argument("--ae-percentile", type=float, default=99.5)
    ap.add_argument("--rf-percentile", type=float, default=99.5)
    args = ap.parse_args()
    if not os.path.exists(args.csv):
        raise SystemExit(
            f"Dataset not found: {args.csv}\n"
            "Mount/unzip your preprocessed CICIDS2017 CSV there (or pass a path) "
            "and re-run. This script needs real benign traffic to calibrate."
        )
    calibrate(args.csv, ae_pct=args.ae_percentile, rf_pct=args.rf_percentile)
