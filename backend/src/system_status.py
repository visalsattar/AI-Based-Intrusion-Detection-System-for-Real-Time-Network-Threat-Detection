# backend/src/system_status.py
"""
Real System Information for the Settings page.

Every value here is either read directly off disk, queried from Redis, or
computed from the running process — nothing is a placeholder. Where an
artifact genuinely doesn't exist yet (most notably the trained model, since
backend/models/ ships empty in a fresh checkout), this reports that
honestly instead of inventing a number — the same pattern your own UI
already uses for "Geolocation DB: Not available (download required)".
"""

import os
import json
import time
import logging

import geo_utils

logger = logging.getLogger("IDS-SystemStatus")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_BASE_DIR, "..", "models", "autoencoder.h5")
SCALER_PATH = os.path.join(_BASE_DIR, "..", "models", "feature_scaler.pkl")
METRICS_PATH = os.path.join(_BASE_DIR, "..", "models", "metrics.json")
REAL_METRICS_PATH = os.path.join(_BASE_DIR, "..", "models", "real_metrics.json")

_PROCESS_START_TIME = time.time()


def get_model_status() -> dict:
    """
    Checks for the actual trained artifacts on disk, AND whether the
    reconstruction-error threshold has been calibrated against real benign
    data (models/real_metrics.json, written by model_evaluation.py). A
    model file existing is not the same as detection being trustworthy —
    without calibration, RealTimeIDSPipeline runs on an explicitly-flagged
    uncalibrated fallback threshold (see ids_pipeline.py).
    """
    model_exists = os.path.exists(MODEL_PATH)
    scaler_exists = os.path.exists(SCALER_PATH)

    if not (model_exists and scaler_exists):
        missing = []
        if not model_exists:
            missing.append("models/autoencoder.h5")
        if not scaler_exists:
            missing.append("models/feature_scaler.pkl")
        return {
            "status": "not_trained",
            "accuracy": None,
            "calibrated": False,
            "message": f"Missing: {', '.join(missing)}. Run `python main.py --mode train` after preprocessing a dataset.",
        }

    accuracy = None
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH) as f:
                metrics = json.load(f)
            accuracy = metrics.get("accuracy") or metrics.get("test_accuracy")
        except Exception as e:
            logger.warning(f"Could not read metrics.json: {e}")

    calibrated = False
    recon_threshold = None
    if os.path.exists(REAL_METRICS_PATH):
        try:
            with open(REAL_METRICS_PATH) as f:
                real_metrics = json.load(f)
            recon_threshold = real_metrics.get("autoencoder", {}).get("threshold")
            accuracy = accuracy or real_metrics.get("autoencoder", {}).get("accuracy")
            calibrated = recon_threshold is not None
        except Exception as e:
            logger.warning(f"Could not read real_metrics.json: {e}")

    if not calibrated:
        return {
            "status": "uncalibrated",
            "accuracy": accuracy,
            "calibrated": False,
            "message": ("Model artifacts present but NOT calibrated — detection is running on a "
                        "placeholder threshold. Run `python src/model_evaluation.py <preprocessed_csv>` "
                        "to calibrate against real benign traffic."),
        }

    return {
        "status": "ready",
        "accuracy": accuracy,
        "calibrated": True,
        "recon_threshold": recon_threshold,
        "message": "Model trained and calibrated against real data.",
    }


def get_uptime_seconds() -> int:
    """Real wall-clock time since this Flask/Socket.IO process started."""
    return int(time.time() - _PROCESS_START_TIME)


def get_log_entry_count(redis_client) -> int:
    """Real count of persisted alerts in the Redis stream, not a session-only counter."""
    if not redis_client:
        return 0
    try:
        return redis_client.xlen("ids:alerts")
    except Exception as e:
        logger.warning(f"Could not read stream length: {e}")
        return 0


def get_full_status(redis_client) -> dict:
    """Aggregate payload for GET /api/system-info."""
    return {
        "model": get_model_status(),
        "geolocation_db": geo_utils.get_status(),
        "uptime_seconds": get_uptime_seconds(),
        "log_entries": get_log_entry_count(redis_client),
        "redis_connected": redis_client is not None,
    }
