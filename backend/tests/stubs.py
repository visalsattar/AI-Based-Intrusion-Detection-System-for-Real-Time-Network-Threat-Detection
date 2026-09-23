"""Model-free stand-ins for the live pipeline (shared by test_flow_scoring.py and test_verify_ensemble.py)."""
import json
import threading
import time

import numpy as np

from feature_order import FEATURE_ORDER
from ids_pipeline import RealTimeIDSPipeline


class StubAE:
    """predict() returns x + delta, so per-row MSE == delta**2 (controllable score)."""
    def __init__(self, delta=0.5):
        self.delta, self.rows_seen = delta, 0

    def predict(self, x, batch_size=None, verbose=0):
        self.rows_seen += len(x)
        return x + self.delta


class StubScaler:
    feature_names_in_ = np.array(FEATURE_ORDER)
    n_features_in_ = 78

    def transform(self, x):
        return x


class RecordingRedis:
    def __init__(self):
        self.calls = []

    def xadd(self, stream, mapping, **kw):
        self.calls.append((stream, mapping, kw))

    def get(self, key):
        return None

    def alerts(self):
        return [json.loads(m["data"]) for _, m, _ in self.calls]


def make_pipeline():
    p = object.__new__(RealTimeIDSPipeline)
    p.alert_threshold = 0.85
    p.packet_batch_size = 10**9
    p.batch_interval = 10**9
    p.flow_idle_timeout = 15.0
    p.flow_max_duration = 120.0
    p.max_packets_per_flow = 2000
    p.max_tracked_flows = 20000
    p.alert_cooldown = 60.0
    p.block_ttl = 900.0
    p.sweep_interval = 0.0          # sweep every call in tests
    p._last_eviction_at = 0.0
    p._last_batch_at = time.time()
    p.redis_client = RecordingRedis()
    p.random_forest = None
    p._rf_multiclass = False
    p._rf_attack_idx = None
    p._label_map = {}
    p.recon_threshold = 0.003154
    p._threshold_calibrated = True
    p.AE_OVERRIDE_CONF, p.RF_OVERRIDE_CONF = 0.97, 0.90
    p.packet_buffer, p.flow_tracker = [], {}
    p._settings_cache, p._settings_loaded_at = {}, time.time() + 1e9   # never hit Redis
    p._last_alert = {}
    p._lock, p._done, p._last_sweep_at = threading.RLock(), set(), 0.0
    p._blocked, p._local_ips, p._local_ips_at = {}, {"10.0.0.5"}, time.time()
    p._whitelist, p._stop = set(), threading.Event()
    p._dump_path, p._dump_rows, p._dump_max = None, 0, 200000
    p.autoencoder, p.feature_scaler = StubAE(), StubScaler()
    return p


