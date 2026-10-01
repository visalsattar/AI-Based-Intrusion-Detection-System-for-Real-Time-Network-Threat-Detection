# backend/src/model_artifacts.py
"""
Preflight for live capture: which trained artifacts must exist before packet capture starts.

Why the Random Forest is required by default: ids_pipeline.py falls back to the autoencoder
alone when random_forest.pkl is missing, and AE-only alerting stays disabled until
IDS_AE_ONLY_ALERTING_VALIDATED=true. Without this check, capture starts, looks healthy,
and raises zero alerts -- an IDS that is running but blind.
"""
import os

_TRUTHY = {"1", "true", "yes"}

AUTOENCODER = "autoencoder.h5"
SCALER = "feature_scaler.pkl"
RANDOM_FOREST = "random_forest.pkl"


def ae_only_alerting_validated(env=None) -> bool:
    env = os.environ if env is None else env
    return env.get("IDS_AE_ONLY_ALERTING_VALIDATED", "false").strip().lower() in _TRUTHY


def missing_live_artifacts(models_dir: str, ae_only_validated: bool) -> list:
    """Absolute paths of required artifacts that do not exist. Empty list = OK to start."""
    required = [AUTOENCODER, SCALER]
    if not ae_only_validated:
        required.append(RANDOM_FOREST)
    paths = [os.path.join(models_dir, name) for name in required]
    return [p for p in paths if not os.path.isfile(p)]