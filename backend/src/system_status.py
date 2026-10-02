# backend/src/system_status.py
"""
Real System Information for the Settings page.

Every value is read off disk, queried from Redis, or computed from the running
process. Status reflects what the live pipeline will ACTUALLY do with the artifacts
present -- not merely whether a model file exists.

Decision table (mirrors ids_pipeline.RealTimeIDSPipeline):
  AE or scaler missing          -> not_trained     (capture refuses to start)
  no calibrated recon threshold -> uncalibrated    (AE scores meaningless)
  RF missing, AE-only unvalidated -> alerts_suppressed (pipeline emits NO alerts)
  RF missing, AE-only validated -> ready (ae_only)
  RF present                    -> ready (ensemble)
"""

import json
import logging
import os
import time

import geo_utils

logger = logging.getLogger("IDS-SystemStatus")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_MODELS = os.path.join(_BASE_DIR, "..", "models")
MODEL_PATH = os.path.join(_MODELS, "autoencoder.h5")
SCALER_PATH = os.path.join(_MODELS, "feature_scaler.pkl")
RF_PATH = os.path.join(_MODELS, "random_forest.pkl")
REAL_METRICS_PATH = os.path.join(_MODELS, "real_metrics.json")
OVERRIDE_PATH = os.path.join(_MODELS, "override_calibration.json")


def _rf_path() -> str:
    """The RF the capture uses: models/<IDS_RF_DIR>/random_forest.pkl when IDS_RF_DIR is set
    (same variable the pipeline reads), else the shipped models/random_forest.pkl."""
    rf_dir = os.environ.get("IDS_RF_DIR", "").strip()
    return os.path.join(_MODELS, rf_dir, "random_forest.pkl") if rf_dir else RF_PATH

# Keep in sync with RealTimeIDSPipeline.AE_OVERRIDE_CONF / RF_OVERRIDE_CONF and
# scoring.OVERRIDE_FLOOR. Duplicated here so the dashboard process does not import
# TensorFlow just to render a status panel.
_DEFAULT_OVERRIDES = {"ae": 0.97, "rf": 0.90}
_OVERRIDE_FLOOR = 0.50

_PROCESS_START_TIME = time.time()


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.warning(f"Could not read {os.path.basename(path)}: {e}")
        return None


def _ae_only_validated() -> bool:
    return os.environ.get("IDS_AE_ONLY_ALERTING_VALIDATED", "false").strip().lower() in {"1", "true", "yes"}


def _override_status() -> dict:
    """Effective (post-clamp) override thresholds, and where they came from."""
    cal = _read_json(OVERRIDE_PATH)
    if not cal:
        return {"source": "coded_defaults", "ae": _DEFAULT_OVERRIDES["ae"],
                "rf": _DEFAULT_OVERRIDES["rf"], "clamped": []}
    eff, clamped = {}, []
    for k in ("ae", "rf"):
        raw = cal.get(f"{k}_override")
        if raw is None:
            eff[k] = _DEFAULT_OVERRIDES[k]
            continue
        raw = float(raw)
        if raw < _OVERRIDE_FLOOR:
            clamped.append(k)
        eff[k] = max(raw, _OVERRIDE_FLOOR)
    return {"source": "override_calibration.json", **eff, "clamped": clamped}


def _offline_metrics(real_metrics) -> dict:
    """
    Offline CICIDS2017 test-split metrics, labelled as such. These are NOT live
    detection rates: live traffic has never been scored against ground truth.
    A single 'accuracy' is deliberately not surfaced -- on an imbalanced dataset
    it is dominated by the benign class.
    """
    if not real_metrics:
        return {"available": False}
    out = {"available": True, "dataset": "CICIDS2017 held-out split (offline)"}
    for model in ("autoencoder", "random_forest"):
        m = real_metrics.get(model) or {}
        picked = {k: m[k] for k in ("precision", "recall", "f1", "roc_auc", "fpr") if k in m}
        if picked:
            out[model] = picked
    return out


def get_model_status() -> dict:
    ae = os.path.exists(MODEL_PATH)
    scaler = os.path.exists(SCALER_PATH)
    rf_path = _rf_path()
    rf = os.path.exists(rf_path)

    if not (ae and scaler):
        missing = [n for n, ok in (("models/autoencoder.h5", ae),
                                   ("models/feature_scaler.pkl", scaler)) if not ok]
        return {
            "status": "not_trained",
            "detection_mode": None,
            "calibrated": False,
            "message": f"Missing: {', '.join(missing)}. Live capture will refuse to start.",
        }

    real_metrics = _read_json(REAL_METRICS_PATH)
    recon_threshold = (real_metrics or {}).get("autoencoder", {}).get("threshold")
    calibrated = bool(recon_threshold)
    overrides = _override_status()
    common = {
        "random_forest_present": rf,
        "random_forest_source": os.environ.get("IDS_RF_DIR", "").strip() or "shipped (CICIDS2017)",
        "calibrated": calibrated,
        "recon_threshold": recon_threshold,
        "override_thresholds": overrides,
        "offline_metrics": _offline_metrics(real_metrics),
    }

    if not calibrated:
        return {**common, "status": "uncalibrated", "detection_mode": None,
                "message": ("Autoencoder threshold is NOT calibrated; scores are meaningless. "
                            "Run `python src/model_evaluation.py <preprocessed_csv>`.")}

    if not rf and not _ae_only_validated():
        return {**common, "status": "alerts_suppressed", "detection_mode": "ae_only_unvalidated",
                "message": ("random_forest.pkl is missing and AE-only alerting has not been "
                            "validated. The pipeline scores flows but emits NO alerts.")}

    msg = ("Ensemble (autoencoder + random forest) active." if rf
           else "Autoencoder-only mode (operator-validated via IDS_AE_ONLY_ALERTING_VALIDATED).")
    if overrides["clamped"]:
        msg += (f" Warning: calibrated override(s) {overrides['clamped']} were below "
                f"{_OVERRIDE_FLOOR} and are clamped; re-run calibration.")
    return {**common, "status": "ready",
            "detection_mode": "ensemble" if rf else "ae_only", "message": msg}


def get_uptime_seconds() -> int:
    """Wall-clock time since this dashboard process started (not the capture process)."""
    return int(time.time() - _PROCESS_START_TIME)


def get_log_entry_count(redis_client):
    """Persisted alerts in the Redis stream. None means unknown (Redis unreachable), not zero."""
    if not redis_client:
        return None
    try:
        return redis_client.xlen("ids:alerts")
    except Exception as e:
        logger.warning(f"Could not read stream length: {e}")
        return None


def _redis_reachable(redis_client) -> bool:
    """Actually ping: main.py builds a lazy client that is never None."""
    if not redis_client:
        return False
    try:
        return bool(redis_client.ping())
    except Exception:
        return False


def get_full_status(redis_client) -> dict:
    """Aggregate payload for GET /api/system-info."""
    return {
        "model": get_model_status(),
        "geolocation_db": geo_utils.get_status(),
        "uptime_seconds": get_uptime_seconds(),
        "log_entries": get_log_entry_count(redis_client),
        "redis_connected": _redis_reachable(redis_client),
    }