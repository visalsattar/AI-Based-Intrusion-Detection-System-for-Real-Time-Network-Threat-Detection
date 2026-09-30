"""
Hardening tests for the live pipeline. Written test-first: most FAIL until the
changes in FIXES.md are applied. Do not weaken an assertion to make one pass.

Place in backend/tests/. Place scoring.py in backend/src/.
"""
import json
import os
import sys
import time
from datetime import datetime, timedelta

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scapy.all import IP, TCP  # noqa: E402

from ids_pipeline import RealTimeIDSPipeline  # noqa: E402
from scoring import attack_probability, clamp_override, sanitize_settings, OVERRIDE_FLOOR  # noqa: E402

ATTACKER = "8.8.8.8"      # deliberately a real, critical, *global* address
LOCAL = "10.0.0.5"


def _shell(**overrides):
    """Pipeline instance without __init__ (no models, no Redis, no capture)."""
    p = RealTimeIDSPipeline.__new__(RealTimeIDSPipeline)
    attrs = dict(
        flow_tracker={}, _done=set(), packet_buffer=[], max_packets_per_flow=2000,
        _whitelist=set(), _blocked={}, _local_ips={LOCAL}, _local_ips_at=time.time(),
        max_tracked_flows=20000, evicted_flows_total=0,
    )
    attrs.update(overrides)
    for k, v in attrs.items():
        setattr(p, k, v)
    return p


def _syn(seq=1000):
    return IP(src=ATTACKER, dst=LOCAL) / TCP(sport=40000, dport=80, flags="S", seq=seq)


def _synack(seq=5000, ack=1001):
    return IP(src=LOCAL, dst=ATTACKER) / TCP(sport=80, dport=40000, flags="SA", seq=seq, ack=ack)


def _ack(ack, seq=1001):
    return IP(src=ATTACKER, dst=LOCAL) / TCP(sport=40000, dport=80, flags="A", seq=seq, ack=ack)


def _only_flow(p):
    assert len(p.flow_tracker) == 1
    return next(iter(p.flow_tracker.values()))


# - 1. spoofed SYN -

class TestAutoBlockRequiresHandshake:
    def test_bare_spoofed_syn_does_not_block(self):
        p = _shell()
        p._ingest(_syn())
        assert p._should_block(_only_flow(p)) is False

    def test_blind_ack_with_wrong_ack_number_does_not_block(self):
        """A blind spoofer never sees our SYN-ACK, so it cannot know seq+1."""
        p = _shell()
        for pkt in (_syn(), _synack(seq=5000), _ack(ack=12345)):
            p._ingest(pkt)
        assert p._should_block(_only_flow(p)) is False

    def test_ack_without_synack_does_not_block(self):
        p = _shell()
        for pkt in (_syn(), _ack(ack=5001)):
            p._ingest(pkt)
        assert p._should_block(_only_flow(p)) is False

    def test_completed_handshake_is_blockable(self):
        p = _shell()
        for pkt in (_syn(), _synack(seq=5000), _ack(ack=5001)):
            p._ingest(pkt)
        assert _only_flow(p).get("handshake_complete") is True
        assert p._should_block(_only_flow(p)) is True

    def test_handshake_ack_wraps_at_2_32(self):
        p = _shell()
        for pkt in (_syn(), _synack(seq=2**32 - 1), _ack(ack=0)):
            p._ingest(pkt)
        assert _only_flow(p).get("handshake_complete") is True

    def test_active_block_cap(self):
        full = {f"203.0.113.{i}": time.time() + 900 for i in range(RealTimeIDSPipeline.MAX_ACTIVE_BLOCKS)}
        p = _shell(_blocked=full)
        for pkt in (_syn(), _synack(seq=5000), _ack(ack=5001)):
            p._ingest(pkt)
        assert p._should_block(_only_flow(p)) is False


# - 2. eviction -

def _flow(age_s):
    t = datetime.now() - timedelta(seconds=age_s)
    return {"last_seen": t, "first_seen": t, "packets": 1}


class TestOverflowEvictionScoresFirst:
    def test_overflow_flows_are_scored_before_deletion(self):
        p = _shell(max_tracked_flows=2,
                   flow_tracker={"old": _flow(30), "mid": _flow(20), "new": _flow(10)})
        scored = []
        p._score_flows = lambda keys: scored.extend(keys)

        evicted = p._evict_overflow()

        assert scored == ["old"]
        assert set(p.flow_tracker) == {"mid", "new"}
        assert evicted == 1 and p.evicted_flows_total == 1

    def test_flows_are_removed_even_if_scoring_fails(self):
        p = _shell(max_tracked_flows=1, flow_tracker={"a": _flow(20), "b": _flow(10)})

        def boom(keys):
            raise RuntimeError("model down")
        p._score_flows = boom

        with pytest.raises(RuntimeError):
            p._evict_overflow()
        assert set(p.flow_tracker) == {"b"}   # memory bound still holds

    def test_under_cap_is_a_noop(self):
        p = _shell(max_tracked_flows=5, flow_tracker={"a": _flow(1)})
        p._score_flows = lambda keys: pytest.fail("should not score")
        assert p._evict_overflow() == 0


# - 3. settings / batch isolation -

class TestMalformedSettings:
    def test_wrong_types_fall_back_to_defaults(self):
        s = sanitize_settings({"criticalThreshold": "0.9", "highThreshold": 2.0,
                               "sensitivity": "nonsense", "autoBlock": "true"})
        assert s == {"sensitivity": "medium", "autoBlock": False,
                     "criticalThreshold": 0.95, "highThreshold": 0.85}

    def test_inverted_thresholds_reset(self):
        s = sanitize_settings({"criticalThreshold": 0.85, "highThreshold": 0.90})
        assert s["highThreshold"] < s["criticalThreshold"]

    def test_non_dict_document(self):
        assert sanitize_settings(["x"])["sensitivity"] == "medium"

    def test_severity_never_raises_on_sanitized_input(self):
        p = _shell()
        assert p._compute_severity(0.97, sanitize_settings({"criticalThreshold": "0.9"})) == "CRITICAL"

    def test_one_bad_flow_does_not_drop_the_rest(self):
        p = _shell()
        handled = []

        def process(key, err, prob, name):
            if key == "bad":
                raise KeyError("flow vanished")
            handled.append(key)
        p._process_prediction = process

        failed = p._dispatch_predictions(["bad", "good1", "good2"],
                                         [0.1, 0.2, 0.3], [0.9, 0.1, 0.2], [None] * 3)
        assert handled == ["good1", "good2"]
        assert failed == 1


# - 4. override calibration -

def _write_cal(tmp_path, **vals):
    (tmp_path / "override_calibration.json").write_text(json.dumps(vals))
    return str(tmp_path / "autoencoder.h5")   # only its dirname is used


class TestOverrideCalibration:
    def test_below_floor_is_clamped(self, tmp_path):
        ae, rf = RealTimeIDSPipeline._load_override_confs(_write_cal(tmp_path, ae_override=0.97, rf_override=0.03))
        assert rf == OVERRIDE_FLOOR and ae == 0.97

    def test_nan_falls_back_to_coded_defaults(self, tmp_path):
        path = tmp_path / "override_calibration.json"
        path.write_text('{"ae_override": NaN, "rf_override": 0.9}')
        ae, rf = RealTimeIDSPipeline._load_override_confs(str(tmp_path / "autoencoder.h5"))
        assert (ae, rf) == (RealTimeIDSPipeline.AE_OVERRIDE_CONF, RealTimeIDSPipeline.RF_OVERRIDE_CONF)

    def test_above_one_rejected(self):
        with pytest.raises(ValueError):
            clamp_override(1.5)


# - 5. attack probability -

class TestAttackProbability:
    def test_binary_matches_class_one_column(self):
        proba = np.array([[0.8, 0.2], [0.1, 0.9]])
        np.testing.assert_allclose(attack_probability(proba, [0, 1]), [0.2, 0.9])

    def test_multiclass_is_one_minus_benign(self):
        # classes: 0=Benign, 1=DDoS, 2=PortScan. Old code returned P(DDoS)=0.05.
        proba = np.array([[0.05, 0.05, 0.90]])
        np.testing.assert_allclose(attack_probability(proba, [0, 1, 2]), [0.95])

    def test_numpy_int_classes(self):
        proba = np.array([[0.7, 0.3]])
        np.testing.assert_allclose(attack_probability(proba, np.array([0, 1])), [0.3])

    def test_missing_benign_class_raises(self):
        with pytest.raises(ValueError):
            attack_probability(np.array([[0.5, 0.5]]), [1, 2])