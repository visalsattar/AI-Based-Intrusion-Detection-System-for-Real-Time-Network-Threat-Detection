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
import time

import numpy as np
import pytest

from scapy.all import IP, TCP

import ids_pipeline
from feature_order import FEATURE_ORDER
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

    def xadd(self, stream, mapping, **kw):   # the pipeline passes maxlen=/approximate=
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

@pytest.fixture(autouse=True)
def _isolate_pipeline(pipeline, monkeypatch):
    """Pin every on-disk input the alert path reads, so results don't depend on local files."""
    pipeline._last_alert.clear()
    pipeline._src_flow_times = {}            # module-scoped pipeline: no rate carry-over
    monkeypatch.setattr(pipeline, "recon_threshold", 0.01)   # ae_score(1.0) = 0.99
    monkeypatch.setattr(pipeline, "_load_settings", lambda: {"sensitivity": "medium", "autoBlock": False})


def _flooding(pipeline, src="10.0.0.5", n=200):
    """Make `src` look like it opened n connections in the last 2 s (rate gate, RATE_* constants)."""
    now = time.time()
    for i in range(n):
        pipeline._note_new_flow(src, now - i * 0.01)


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


def test_scaler_feature_names_match_extractor_order(pipeline):
    """
    The fitted scaler's column order must equal the order _extract_flow_features emits.
    A shape check cannot catch a column shift (shape stays (78,)); this can. If it fails, either
    tests/feature_order.py has a typo against the real CICIDS header, or the extractor drifted.
    """
    names = [str(n) for n in pipeline.feature_scaler.feature_names_in_]
    diffs = [(i, a, b) for i, (a, b) in enumerate(zip(names, FEATURE_ORDER)) if a != b]
    assert names == FEATURE_ORDER, f"{len(diffs)} mismatches, first: {diffs[:5]}"


def test_idle_flows_are_evicted(pipeline):
    """A flow whose last packet is older than flow_idle_timeout is dropped."""
    from datetime import datetime, timedelta

    flow_key = _make_flow(pipeline)
    # Backdate last_seen well past the timeout.
    pipeline.flow_tracker[flow_key]["last_seen"] = (
        datetime.now() - timedelta(seconds=pipeline.flow_idle_timeout + 10)
    )
    pipeline._evict_stale_flows()
    assert flow_key not in pipeline.flow_tracker, "stale flow was not evicted"


def test_hard_cap_evicts_oldest_flows(pipeline):
    """When over max_tracked_flows, the oldest flows are evicted first."""
    from datetime import datetime, timedelta

    original_cap = pipeline.max_tracked_flows
    pipeline.flow_tracker.clear()
    pipeline.max_tracked_flows = 5
    try:
        now = datetime.now()
        # 8 fresh flows (none idle) so only the hard cap can act.
        for i in range(8):
            key = (("10.0.0.%d" % i, 1000 + i), ("10.0.0.254", 80), 6)
            pipeline.flow_tracker[key] = {
                "packets": 1, "bytes": 40,
                "first_seen": now, "last_seen": now - timedelta(seconds=i),
                "protocol": 6, "packet_list": [],
                "init_src": "10.0.0.%d" % i, "init_sport": 1000 + i,
                "init_dst": "10.0.0.254", "init_dport": 80,
                "fwd_win": None, "bwd_win": None,
            }
        pipeline._evict_stale_flows()
        assert len(pipeline.flow_tracker) == 5, "table not trimmed to cap"
        # The three oldest (largest i -> older last_seen) should be gone.
        remaining_srcs = {f["init_src"] for f in pipeline.flow_tracker.values()}
        assert "10.0.0.7" not in remaining_srcs and "10.0.0.5" not in remaining_srcs
    finally:
        pipeline.max_tracked_flows = original_cap
        pipeline.flow_tracker.clear()


def test_override_confs_fall_back_to_defaults(pipeline):
    """
    With no override_calibration.json present, the pipeline must use the coded
    class defaults (AE 0.97 / RF 0.90). calibrate_override.py can later write
    that file to tighten these from real benign data.
    """
    cal = os.path.join(BACKEND_DIR, "models", "override_calibration.json")
    if not os.path.exists(cal):
        assert pipeline.AE_OVERRIDE_CONF == pytest.approx(0.97)
        assert pipeline.RF_OVERRIDE_CONF == pytest.approx(0.90)


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
    pipeline.ae_only_alerting_validated = True
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
    _flooding(pipeline)                  # RF verdicts need a source that is actually flooding

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


def test_unconfirmed_ae_override_is_capped_and_never_autoblocks(pipeline, monkeypatch):
    """Live benign capture (1 Oct 2026): every false alert was an AE override on a large
    download, some CRITICAL. An override the RF does not confirm is capped at MEDIUM, so it
    can never reach the CRITICAL-only AutoBlock path."""
    pipeline.redis_client = FakeRedis()
    blocked = []
    monkeypatch.setattr(pipeline, "_load_settings", lambda: {"autoBlock": True})
    monkeypatch.setattr(pipeline, "_should_block", lambda flow: True)
    monkeypatch.setattr(pipeline, "_block", blocked.append)
    flow_key = _make_flow(pipeline)

    pipeline._process_prediction(flow_key, recon_error=1000.0, rf_attack_prob=0.05)

    alert = pipeline.redis_client.alerts()[0]
    assert alert["anomaly_score"] > 0.97           # score itself is not hidden
    assert alert["severity"] == pipeline.AE_OVERRIDE_MAX_SEVERITY == "MEDIUM"
    assert blocked == []


def test_moderate_rf_alone_alerts_at_medium_and_never_autoblocks(pipeline, monkeypatch):
    """CICIDS pcap replay: RF P(attack) 0.7-0.9 with a calm AE was missed by the fused rule."""
    pipeline.redis_client = FakeRedis()
    blocked = []
    monkeypatch.setattr(pipeline, "_load_settings", lambda: {"autoBlock": True})
    monkeypatch.setattr(pipeline, "_should_block", lambda flow: True)
    monkeypatch.setattr(pipeline, "_block", blocked.append)
    flow_key = _make_flow(pipeline)
    _flooding(pipeline)                  # RF verdicts need a source that is actually flooding

    pipeline._process_prediction(flow_key, recon_error=0.0001, rf_attack_prob=0.75)

    alert = pipeline.redis_client.alerts()[0]
    assert alert["detection_source"] == "random forest (moderate confidence)"
    assert alert["severity"] == "MEDIUM"
    assert alert["anomaly_score"] == pytest.approx(0.75)
    assert blocked == []


def test_low_sensitivity_disables_the_moderate_rf_path(pipeline, monkeypatch):
    pipeline.redis_client = FakeRedis()
    monkeypatch.setattr(pipeline, "_load_settings", lambda: {"sensitivity": "low"})
    flow_key = _make_flow(pipeline)
    pipeline._process_prediction(flow_key, recon_error=0.0001, rf_attack_prob=0.75)
    assert pipeline.redis_client.alerts() == []


def test_rf_below_moderate_threshold_with_calm_ae_does_not_alert(pipeline):
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)
    pipeline._process_prediction(flow_key, recon_error=0.0001, rf_attack_prob=0.65)
    assert pipeline.redis_client.alerts() == []


def test_ids_rf_dir_loads_rf_and_label_map_from_that_directory(tmp_path, monkeypatch):
    """IDS_RF_DIR swaps in a live-trained RF (train_live_flow.py) and its threat names."""
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    rf = RandomForestClassifier(n_estimators=2, random_state=0).fit(
        np.r_[np.zeros((4, 78)), np.ones((4, 78))], [0] * 4 + [1] * 4)
    joblib.dump(rf, tmp_path / "random_forest.pkl")
    (tmp_path / "label_map.json").write_text('{"0": "Benign", "1": "Lab Flood"}')
    monkeypatch.setenv("IDS_RF_DIR", str(tmp_path))      # absolute path wins over models/

    ids = RealTimeIDSPipeline(model_path=MODEL_PATH, feature_extractor_path=SCALER_PATH)

    assert os.path.normpath(ids.rf_dir) == os.path.normpath(str(tmp_path))
    assert ids.random_forest.n_estimators == 2
    assert ids._label_map == {0: "Benign", 1: "Lab Flood"}


def test_default_rf_dir_is_models_directory(monkeypatch):
    monkeypatch.delenv("IDS_RF_DIR", raising=False)
    ids = RealTimeIDSPipeline(model_path=MODEL_PATH, feature_extractor_path=SCALER_PATH)
    assert os.path.normpath(ids.rf_dir) == os.path.normpath(os.path.dirname(MODEL_PATH))


def test_rf_confirmed_attack_still_reaches_critical_and_autoblock(pipeline, monkeypatch):
    pipeline.redis_client = FakeRedis()
    blocked = []
    monkeypatch.setattr(pipeline, "_load_settings", lambda: {"autoBlock": True})
    monkeypatch.setattr(pipeline, "_should_block", lambda flow: True)
    monkeypatch.setattr(pipeline, "_block", blocked.append)
    flow_key = _make_flow(pipeline)
    _flooding(pipeline)                  # RF verdicts need a source that is actually flooding

    pipeline._process_prediction(flow_key, recon_error=1000.0, rf_attack_prob=0.99)

    alert = pipeline.redis_client.alerts()[0]
    assert alert["severity"] == "CRITICAL"
    assert len(blocked) == 1


def test_rf_override_confirms_known_attack(pipeline):
    """A very confident RF (P(attack) > 0.90) must alert even if the AE is calm."""
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)
    _flooding(pipeline)                  # RF verdicts need a source that is actually flooding

    # recon_error 0 -> ae_score 0 (AE calm); RF very confident it's an attack.
    pipeline._process_prediction(flow_key, recon_error=0.0, rf_attack_prob=0.95)

    alerts = pipeline.redis_client.alerts()
    assert len(alerts) == 1, "RF override failed to fire on a known-attack pattern"
    assert "random forest override" in alerts[0]["detection_source"]
    assert alerts[0]["anomaly_score"] == pytest.approx(0.95, abs=1e-6)

def test_cooldown_suppresses_duplicate_alerts(pipeline):
    pipeline.redis_client = FakeRedis()
    pipeline.ae_only_alerting_validated = True
    key = _make_flow(pipeline)
    pipeline._process_prediction(key, recon_error=1.0, rf_attack_prob=None)
    pipeline._process_prediction(key, recon_error=1.0, rf_attack_prob=None)
    assert len(pipeline.redis_client.alerts()) == 1

def test_done_flow_is_scored_once_and_removed(pipeline):
    pipeline.redis_client = FakeRedis()
    key = _make_flow(pipeline)
    pipeline.flow_tracker[key]['done'] = True
    pipeline._done.add(key)   # what _ingest() does when it sees FIN/RST
    pipeline.packet_buffer.append((key, None))
    pipeline._inference_batch()
    assert key not in pipeline.flow_tracker

# - per-source connection-rate rules (RATE_* constants; 2 Oct 2026)

def test_rf_verdict_from_a_quiet_source_does_not_alert(pipeline):
    """live_flow_v2 flagged 99% of human-paced GETs: one RF-positive connection is not a flood."""
    pipeline.redis_client = FakeRedis()
    gated_before = getattr(pipeline, "_rate_gated", 0)
    flow_key = _make_flow(pipeline)                       # a single connection, no flood
    pipeline._process_prediction(flow_key, recon_error=0.0001, rf_attack_prob=0.99)
    assert pipeline.redis_client.alerts() == []
    assert pipeline._rate_gated == gated_before + 1


def test_high_connection_rate_alerts_without_any_model(pipeline):
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)
    _flooding(pipeline, n=400)                            # ~40 conn/s over the 10 s window
    pipeline._process_prediction(flow_key, recon_error=0.0001, rf_attack_prob=0.05)
    alert = pipeline.redis_client.alerts()[0]
    assert alert["detection_source"] == "connection-rate flood"
    assert alert["threat_type"] == "Connection Flood (rate)"
    assert alert["severity"] == "HIGH"
    assert alert["src_conn_rate"] >= pipeline.RATE_FLOOD_CONN_PER_S


def test_moderate_rate_below_flood_threshold_raises_nothing_on_its_own(pipeline):
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)
    _flooding(pipeline, n=150)                            # 15 conn/s: above RF gate, below flood rule
    pipeline._process_prediction(flow_key, recon_error=0.0001, rf_attack_prob=0.05)
    assert pipeline.redis_client.alerts() == []


def test_source_rate_counts_only_the_window():
    p = RealTimeIDSPipeline.__new__(RealTimeIDSPipeline)
    for t in (0.0, 1.0, 2.0, 50.0):
        p._note_new_flow("1.2.3.4", t)
    assert p._source_rate("1.2.3.4", 50.0) == pytest.approx(1 / p.RATE_WINDOW_S)
    assert p._source_rate("9.9.9.9", 50.0) == 0.0


def test_ae_led_alert_does_not_borrow_the_rf_attack_name(pipeline):
    pipeline.redis_client = FakeRedis()
    flow_key = _make_flow(pipeline)
    # AE screaming (override), RF mildly positive and naming an attack class.
    pipeline._process_prediction(flow_key, recon_error=1000.0, rf_attack_prob=0.6, threat_name="DDoS")
    alert = pipeline.redis_client.alerts()[0]
    assert alert["detection_source"].startswith("autoencoder override")
    assert alert["threat_type"] == "Network Anomaly"
