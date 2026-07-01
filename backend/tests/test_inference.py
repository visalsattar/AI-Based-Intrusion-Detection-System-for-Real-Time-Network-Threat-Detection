"""
Real tests for the live inference pipeline (ids_pipeline.RealTimeIDSPipeline).

Covers:
  - feature extraction produces a correctly-sized 78-feature vector aligned
    to the fitted scaler,
  - severity banding respects the configurable Critical/High thresholds,
  - alert gating only fires above alert_threshold,
  - the new autoencoder+RandomForest score fusion behaves as specified.

Loads the real trained models once (module-scoped fixture). Redis is faked,
so no Redis server is required. Skips cleanly if the model artifacts aren't
present (e.g. a fresh clone before training).
"""
import json
import os

import numpy as np
import pytest

from scapy.all import IP, TCP

import ids_pipeline
from ids_pipeline import RealTimeIDSPipeline

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_PATH = os.path.join(BACKEND_DIR, "models", "autoencoder.h5")
SCALER_PATH = os.path.join(BACKEND_DIR, "models", "feature_scaler.pkl")

pytestmark = pytest.mark.skipif(
    not (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)),
    reason="Trained model artifacts not present — run `python main.py --mode train` first.",
)


class FakeRedis:
    """Minimal stand-in: records xadd calls, returns no stored settings."""

    def __init__(self):
        self.added = []

    def get(self, key):
        return None

    def xadd(self, stream, mapping):
        self.added.append((stream, mapping))

    def alerts(self):
        return [json.loads(m["data"]) for _, m in self.added]


@pytest.fixture(scope="module")
def pipeline():
    ids = RealTimeIDSPipeline(
        model_path=MODEL_PATH,
        feature_extractor_path=SCALER_PATH,
        alert_threshold=0.85,
        packet_batch_size=1000,  # high, so manual flows never auto-trigger a batch
    )
    return ids


def _make_flow(pipeline, src="10.0.0.5", dst="10.0.0.9", sport=44444, dport=80, n=4):
    """Register a synthetic TCP flow directly in the pipeline's flow_tracker."""
    from datetime import datetime

    proto = 6  # TCP
    flow_key = tuple(sorted([(src, sport), (dst, dport)])) + (proto,)
    pkts = []
    for i in range(n):
        # alternate direction so both fwd and bwd stats are exercised
        if i % 2 == 0:
            p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
            is_fwd = True
        else:
            p = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A")
            is_fwd = False
        pkts.append((p, is_fwd))

    now = datetime.now()
    pipeline.flow_tracker[flow_key] = {
        "packets": n,
        "bytes": sum(len(p) for p, _ in pkts),
        "first_seen": now,
        "last_seen": now,
        "protocol": proto,
        "packet_list": pkts,
        "init_src": src,
        "init_sport": sport,
        "init_dst": dst,
        "init_dport": dport,
        "fwd_win": 8192,
        "bwd_win": 8192,
    }
    return flow_key


def test_feature_vector_is_78_and_scaler_aligned(pipeline):
    """Extracted vector must match the fitted scaler's expected feature count."""
    flow_key = _make_flow(pipeline)
    features = pipeline._extract_flow_features(flow_key)

    assert features is not None
    assert features.shape == (78,), f"expected 78 features, got {features.shape}"
    assert features.shape[0] == pipeline.feature_scaler.n_features_in_
    assert np.isfinite(features).all(), "feature vector contains NaN/Inf"


def test_severity_bands(pipeline):
    """Severity must respect the default Critical=0.95 / High=0.85 thresholds."""
    assert pipeline._compute_severity(0.97) == "CRITICAL"
    assert pipeline._compute_severity(0.90) == "HIGH"
    assert pipeline._compute_severity(0.50) == "MEDIUM"


def test_custom_thresholds_from_settings(pipeline):
    """Settings-page thresholds override the defaults."""
    settings = {"criticalThreshold": 0.80, "highThreshold": 0.60}
    assert pipeline._compute_severity(0.85, settings) == "CRITICAL"
    assert pipeline._compute_severity(0.70, settings) == "HIGH"


def test_alert_gating_below_threshold_is_silent(pipeline):
    """A tiny reconstruction error (AE-only) must not raise an alert."""
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)

    pipeline._process_prediction(flow_key, recon_error=0.0, rf_attack_prob=None)

    assert pipeline.redis_client.alerts() == [], "alert fired below threshold"


def test_alert_fires_above_threshold(pipeline):
    """A large reconstruction error must raise exactly one alert."""
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)

    pipeline._process_prediction(flow_key, recon_error=1.0, rf_attack_prob=None)

    alerts = pipeline.redis_client.alerts()
    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "10.0.0.5", "alert reported the wrong source IP"
    assert alerts[0]["anomaly_score"] > pipeline.alert_threshold


def test_fusion_averages_when_neither_model_overrides(pipeline):
    """
    When both models are only moderately confident, anomaly_score is the plain
    0.5*ae + 0.5*rf average and no override tag is set.
    """
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)

    # recon_error == threshold -> ae_score == 0.5 exactly; rf = 0.6.
    # Neither exceeds its override (AE 0.97 / RF 0.90) -> fused = 0.55.
    original = pipeline.alert_threshold
    pipeline.alert_threshold = 0.4
    try:
        pipeline._process_prediction(
            flow_key, recon_error=pipeline.recon_threshold, rf_attack_prob=0.6
        )
    finally:
        pipeline.alert_threshold = original

    alert = pipeline.redis_client.alerts()[0]
    assert alert["ae_anomaly_score"] == pytest.approx(0.5, abs=1e-3)
    assert alert["anomaly_score"] == pytest.approx(0.55, abs=1e-3)
    assert alert["detection_source"] == "ensemble (autoencoder + random forest)"


def test_ae_override_catches_novel_attack(pipeline):
    """
    THE key regression test for the SYN-flood finding: a screaming autoencoder
    (ae > 0.97) must alert even when the RF disagrees (low P(attack)) — a plain
    average would have vetoed it. This is the whole point of the override.
    """
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)

    # Huge reconstruction error -> ae_score ~ 1.0; RF says benign (0.05).
    pipeline._process_prediction(flow_key, recon_error=1000.0, rf_attack_prob=0.05)

    alerts = pipeline.redis_client.alerts()
    assert len(alerts) == 1, "AE override failed to fire on a novel-attack pattern"
    assert "autoencoder override" in alerts[0]["detection_source"]
    assert alerts[0]["anomaly_score"] > 0.97


def test_rf_override_confirms_known_attack(pipeline):
    """A very confident RF (P(attack) > 0.90) must alert even if the AE is calm."""
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)

    # recon_error 0 -> ae_score 0 (AE calm); RF very confident it's an attack.
    pipeline._process_prediction(flow_key, recon_error=0.0, rf_attack_prob=0.95)

    alerts = pipeline.redis_client.alerts()
    assert len(alerts) == 1, "RF override failed to fire on a known-attack pattern"
    assert "random forest override" in alerts[0]["detection_source"]
    assert alerts[0]["anomaly_score"] == pytest.approx(0.95, abs=1e-6)
