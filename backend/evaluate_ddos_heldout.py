"""Step 5: DDoS-specific analysis on the existing held-out CICIDS2017 test split.

This deliberately does NOT score the full raw CSV. The raw Friday DDoS CSV is the
source dataset behind the cleaned 225,745-row artifact, so scoring all raw rows would
include training data and invalidate the result.

Method:
- Load the same cleaned 78-feature dataset used by the existing evaluation.
- Recreate the project's deterministic split: 158,022 train / 22,574 validation /
  45,149 test (no shuffle).
- Verify the raw CSV labels agree row-for-row with the cleaned binary labels.
- Recover the raw DDoS/BENIGN names for the exact held-out test rows.
- Evaluate RF, AE, and live-style RF+AE fusion without fitting/retraining.
- Derive the AE threshold from BENIGN TRAINING reconstruction errors only.
- Reproduce live fusion: AE score = e/(e+threshold), 0.5/0.5 fusion,
  AE > 0.97 or RF P(attack) > 0.90 override.

CNN is intentionally excluded: it is an offline sequence comparison, not part of
live inference, and Step 5 here targets flow-level/live-path behavior.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
try:
    from src.sequence_builder import build_cnn_sequences
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "Cannot import src.sequence_builder. Run this script from the backend directory "
        "with backend/src/sequence_builder.py present."
    ) from exc

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


DEFAULT_CLEAN = Path("data/preprocessed/CICIDS2017_cleaned.csv")
DEFAULT_RAW = Path("data/CICIDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
DEFAULT_MODELS = Path("models")
DEFAULT_OUTPUT = Path("evidence/ddos_heldout_metrics.json")

AE_OVERRIDE_CONF = 0.97
RF_OVERRIDE_CONF = 0.90


def metrics(y_true: np.ndarray, y_pred: np.ndarray, score: np.ndarray | None = None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_ddos": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall_ddos": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_ddos": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "support": {"benign": int(tn + fp), "ddos": int(fn + tp)},
    }
    if score is not None:
        out["roc_auc"] = float(roc_auc_score(y_true, score))
    return out


def verify_raw_labels(raw_path: Path, expected_y: np.ndarray, test_start: int) -> dict:
    raw_label = pd.read_csv(raw_path, usecols=[78], low_memory=False)
    raw_label.columns = ["Label"]
    mapped = (
        raw_label["Label"].astype(str).str.strip().str.upper()
        .map({"BENIGN": 0, "DDOS": 1})
    )
    if mapped.isna().any():
        raise ValueError(f"Unexpected raw labels: {sorted(raw_label.loc[mapped.isna(), 'Label'].unique())}")
    raw_y = mapped.to_numpy(dtype=np.int64)
    if len(raw_y) != test_start + len(expected_y):
        raise ValueError("Raw/clean dataset row counts differ.")
    exact = bool(np.array_equal(raw_y, np.concatenate([np.zeros(0, dtype=np.int64), raw_y])))
    # The useful check is the exact test slice against the cleaned test labels.
    test_match = bool(np.array_equal(raw_y[test_start:], expected_y))
    return {
        "raw_rows": int(len(raw_y)),
        "raw_test_slice_rows": int(len(raw_y[test_start:])),
        "exact_test_label_agreement": test_match,
        "raw_test_benign": int((raw_y[test_start:] == 0).sum()),
        "raw_test_ddos": int((raw_y[test_start:] == 1).sum()),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clean", type=Path, default=DEFAULT_CLEAN)
    ap.add_argument("--raw", type=Path, default=DEFAULT_RAW)
    ap.add_argument("--models", type=Path, default=DEFAULT_MODELS)
    ap.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = ap.parse_args()

    for p in (args.clean, args.raw):
        if not p.exists():
            raise FileNotFoundError(p)

    ae_path = args.models / "autoencoder.h5"
    rf_path = args.models / "random_forest.pkl"
    for p in (ae_path, rf_path):
        if not p.exists():
            raise FileNotFoundError(f"Required artifact missing: {p}")

    data = build_cnn_sequences(str(args.clean), window_size=100, stride=10)
    X_train = data["X_train_flat"]
    y_train = data["y_train_flat"].astype(int)
    X_test = data["X_test_flat"]
    y_test = data["y_test_flat"].astype(int)

    # Reconfirm exact deterministic split sizes rather than assuming them.
    test_start = len(X_train) + len(data["X_val_flat"])
    if len(X_test) != 45149 or len(X_train) != 158022 or len(data["X_val_flat"]) != 22574:
        raise RuntimeError(
            f"Unexpected split: train={len(X_train)}, val={len(data['X_val_flat'])}, test={len(X_test)}"
        )

    raw_check = verify_raw_labels(args.raw, y_test, test_start)
    if not raw_check["exact_test_label_agreement"]:
        raise RuntimeError("Raw DDoS/BENIGN labels do not exactly match the cleaned test labels.")

    # AE threshold: benign TRAINING data only, exactly as model_evaluation.py does it.
    print("Loading Autoencoder...")
    ae = tf.keras.models.load_model(ae_path, compile=False)
    X_train_benign = X_train[y_train == 0]
    train_recon = ae.predict(X_train_benign, batch_size=1024, verbose=0)
    train_mse = np.mean(np.square(X_train_benign - train_recon), axis=1)
    threshold = float(np.percentile(train_mse, 90))

    test_recon = ae.predict(X_test, batch_size=1024, verbose=0)
    ae_mse = np.mean(np.square(X_test - test_recon), axis=1)
    ae_pred = (ae_mse > threshold).astype(int)
    ae_score = ae_mse / (ae_mse + threshold)

    print("Loading Random Forest...")
    rf = joblib.load(rf_path)
    rf_prob = rf.predict_proba(X_test)[:, 1]
    rf_pred = (rf_prob >= 0.5).astype(int)

    # Exact live fusion semantics from ids_pipeline._process_prediction().
    fusion_score = 0.5 * ae_score + 0.5 * rf_prob
    fusion_pred = (fusion_score >= 0.5).astype(int)
    ae_override = ae_score > AE_OVERRIDE_CONF
    rf_override = rf_prob > RF_OVERRIDE_CONF
    fusion_pred[ae_override | rf_override] = 1

    results = {
        "methodology": {
            "claim_scope": "DDoS-specific analysis of the existing held-out CICIDS2017 flow-level test split",
            "not_external_validation": True,
            "reason": "The raw Friday DDoS CSV is the source dataset behind the cleaned artifact; scoring all raw rows would include training data.",
            "split": {"train": 158022, "validation": 22574, "test": 45149, "shuffle": False},
            "models_retrained": False,
            "scaler_refit": False,
            "cnn_included": False,
            "cnn_note": "CNN remains an offline sequence comparison and is not part of live inference.",
            "raw_label_verification": raw_check,
        },
        "test_population": {
            "rows": int(len(y_test)),
            "benign": int((y_test == 0).sum()),
            "ddos": int((y_test == 1).sum()),
            "ddos_prevalence": float(y_test.mean()),
        },
        "autoencoder": metrics(y_test, ae_pred, ae_score),
        "random_forest": metrics(y_test, rf_pred, rf_prob),
        "fusion": metrics(y_test, fusion_pred, fusion_score),
        "fusion_diagnostics": {
            "ae_threshold_90th_percentile_train_benign": threshold,
            "ae_override_count": int(ae_override.sum()),
            "rf_override_count": int(rf_override.sum()),
            "either_override_count": int((ae_override | rf_override).sum()),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("\n=== STEP 5: HELD-OUT DDoS ANALYSIS ===")
    print(f"Test rows: {len(y_test):,} | BENIGN: {(y_test == 0).sum():,} | DDoS: {(y_test == 1).sum():,}")
    for name in ("autoencoder", "random_forest", "fusion"):
        m = results[name]
        print(
            f"{name:14s} accuracy={m['accuracy']:.6f} "
            f"precision={m['precision_ddos']:.6f} recall={m['recall_ddos']:.6f} "
            f"f1={m['f1_ddos']:.6f} fpr={m['false_positive_rate']:.6f} "
            f"fnr={m['false_negative_rate']:.6f}"
        )
        print(f"                 CM={m['confusion_matrix']}")
    print(f"\nSaved: {args.output}")


if __name__ == "__main__":
    main()

