"""Feature-parity tests for the live CICFlowMeter-style extractor.

Copy into backend/tests/ when running the project's real test environment.
These tests require the backend's normal Scapy/project dependencies.
"""
from datetime import datetime

import numpy as np

from scapy.all import IP, TCP, Raw

from ids_pipeline import RealTimeIDSPipeline


def _pipeline_with_packets(packets, directions):
    obj = RealTimeIDSPipeline.__new__(RealTimeIDSPipeline)
    key = ("test",)
    obj.flow_tracker = {
        key: {
            "packet_list": list(zip(packets, directions)),
            "first_seen": datetime.now(),
            "last_seen": datetime.now(),
            "init_dport": 80,
            "fwd_win": 4096,
            "bwd_win": 8192,
        }
    }
    return obj, key


def _tcp(src, dst, flags="PA", payload=b"x", t=0.0, win=4096):
    p = IP(src=src, dst=dst) / TCP(sport=1234, dport=80, flags=flags, window=win) / Raw(payload)
    p.time = t
    return p


def test_feature_vector_is_78_columns_and_flag_fields_are_counts():
    packets = [
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"a", 0.0),
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"b", 0.1),
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"c", 0.2),
    ]
    obj, key = _pipeline_with_packets(packets, [True, True, True])
    f = obj._extract_flow_features(key)

    assert f.shape == (78,)
    assert f[30] == 3       # Fwd PSH Flags
    assert f[46] == 3       # PSH Flag Count
    assert f[47] == 3       # ACK Flag Count


def test_subflow_bulk_and_active_idle_statistics_are_populated():
    packets = [
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"a" * 10, 0.0),
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"b" * 10, 0.1),
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"c" * 10, 0.2),
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"d" * 10, 0.3),
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"e" * 10, 6.0),
    ]
    obj, key = _pipeline_with_packets(packets, [True] * len(packets))
    f = obj._extract_flow_features(key)

    # One >1s boundary => sfCount=1 in CICFlowMeter's implementation.
    assert f[62] == 5
    assert f[63] == 50
    # First four payload packets form one bulk.
    assert f[56] == 40
    assert f[57] == 4
    assert f[58] == 133
    # Active intervals: 0.3s and 0.0s after the isolated final packet.
    assert f[70] == 300000
    assert f[73] == 300000
    # Idle gap from 0.3s to 6.0s (> the 5s activity timeout used by CICIDS2017).
    assert f[74] == 5700000
    assert f[77] == 5700000


def test_gap_under_activity_timeout_is_not_idle():
    """CICIDS2017 idle values are all >= 5s (min seen: 5,000,005 us in Friday-DDoS)."""
    packets = [
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"a" * 10, 0.0),
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"b" * 10, 0.1),
        _tcp("10.0.0.1", "10.0.0.2", "PA", b"c" * 10, 2.0),
    ]
    obj, key = _pipeline_with_packets(packets, [True] * len(packets))
    f = obj._extract_flow_features(key)
    assert f[74] == 0 and f[77] == 0   # Idle Mean / Idle Min


def test_training_zero_features_match_scaler_premise():
    """The six Bulk features are zeroed before scaling because the scaler saw only zeros."""
    import os
    import joblib
    path = os.path.join(os.path.dirname(__file__), "..", "models", "feature_scaler.pkl")
    scaler = joblib.load(path)
    names = list(scaler.feature_names_in_)
    for col in RealTimeIDSPipeline.TRAINING_ZERO_FEATURES:
        i = names.index(col)
        assert scaler.data_min_[i] == 0 and scaler.data_max_[i] == 0, col


def test_training_binary_features_match_scaler_premise():
    """Flag columns are clamped to presence (0/1) before scaling because the training CSV only holds 0/1."""
    import os
    import joblib
    path = os.path.join(os.path.dirname(__file__), "..", "models", "feature_scaler.pkl")
    scaler = joblib.load(path)
    names = list(scaler.feature_names_in_)
    for col in RealTimeIDSPipeline.TRAINING_BINARY_FEATURES:
        i = names.index(col)
        assert scaler.data_min_[i] == 0 and scaler.data_max_[i] == 1, col


def test_single_packet_flow_without_window_uses_minus_one():
    # The extractor's UDP path is exercised indirectly here by using a TCP packet
    # without relying on a captured TCP window for the missing direction.
    p = _tcp("10.0.0.1", "10.0.0.2", "S", b"", 0.0)
    obj, key = _pipeline_with_packets([p], [True])
    obj.flow_tracker[key]["fwd_win"] = None
    obj.flow_tracker[key]["bwd_win"] = None
    f = obj._extract_flow_features(key)
    assert f[66] == -1
    assert f[67] == -1
    assert f[68] == 0
    assert np.isfinite(f).all()
