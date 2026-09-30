"""Round 3: system_status truthfulness, bridge room isolation, socket auth."""
import json
import os
import sys

import pytest

import redis_alert_bridge
import system_status


# ---------------------------------------------------------------- system_status

@pytest.fixture
def models(tmp_path, monkeypatch):
    d = tmp_path
    for attr, name in (("MODEL_PATH", "autoencoder.h5"), ("SCALER_PATH", "feature_scaler.pkl"),
                       ("RF_PATH", "random_forest.pkl"), ("REAL_METRICS_PATH", "real_metrics.json"),
                       ("OVERRIDE_PATH", "override_calibration.json")):
        monkeypatch.setattr(system_status, attr, str(d / name))
    monkeypatch.delenv("IDS_AE_ONLY_ALERTING_VALIDATED", raising=False)

    def make(*names, metrics=None, overrides=None):
        for n in names:
            (d / n).write_bytes(b"x")
        if metrics is not None:
            (d / "real_metrics.json").write_text(json.dumps(metrics))
        if overrides is not None:
            (d / "override_calibration.json").write_text(json.dumps(overrides))
    return make


CAL = {"autoencoder": {"threshold": 0.0031, "recall": 0.8, "accuracy": 0.99}}


def test_missing_rf_reports_alerts_suppressed_not_ready(models):
    models("autoencoder.h5", "feature_scaler.pkl", metrics=CAL)
    s = system_status.get_model_status()
    assert s["status"] == "alerts_suppressed"
    assert s["random_forest_present"] is False


def test_ae_only_ready_only_when_validated(models, monkeypatch):
    models("autoencoder.h5", "feature_scaler.pkl", metrics=CAL)
    monkeypatch.setenv("IDS_AE_ONLY_ALERTING_VALIDATED", "true")
    s = system_status.get_model_status()
    assert s["status"] == "ready" and s["detection_mode"] == "ae_only"


def test_ensemble_ready(models):
    models("autoencoder.h5", "feature_scaler.pkl", "random_forest.pkl", metrics=CAL)
    s = system_status.get_model_status()
    assert s["status"] == "ready" and s["detection_mode"] == "ensemble"


def test_uncalibrated(models):
    models("autoencoder.h5", "feature_scaler.pkl", "random_forest.pkl")
    assert system_status.get_model_status()["status"] == "uncalibrated"


def test_not_trained(models):
    assert system_status.get_model_status()["status"] == "not_trained"


def test_accuracy_is_not_surfaced_and_metrics_labelled_offline(models):
    models("autoencoder.h5", "feature_scaler.pkl", "random_forest.pkl", metrics=CAL)
    s = system_status.get_model_status()
    assert "accuracy" not in s
    assert "accuracy" not in s["offline_metrics"].get("autoencoder", {})
    assert "offline" in s["offline_metrics"]["dataset"]


def test_clamped_override_is_reported(models):
    models("autoencoder.h5", "feature_scaler.pkl", "random_forest.pkl", metrics=CAL,
           overrides={"ae_override": 0.82, "rf_override": 0.0229})
    o = system_status.get_model_status()["override_thresholds"]
    assert o["rf"] == 0.50 and o["clamped"] == ["rf"] and o["ae"] == 0.82


def test_defaults_when_no_override_file(models):
    models("autoencoder.h5", "feature_scaler.pkl", "random_forest.pkl", metrics=CAL)
    o = system_status.get_model_status()["override_thresholds"]
    assert o["source"] == "coded_defaults" and o["ae"] == 0.97 and o["rf"] == 0.90


class _DeadRedis:
    def ping(self):
        raise ConnectionError("down")

    def xlen(self, k):
        raise ConnectionError("down")


def test_redis_connected_pings_instead_of_trusting_non_none_client():
    assert system_status._redis_reachable(_DeadRedis()) is False
    assert system_status.get_log_entry_count(_DeadRedis()) is None


# ---------------------------------------------------------------- bridge

class _StopLoop(Exception):
    pass


class _FakeSocketIO:
    def __init__(self):
        self.emitted = []

    def emit(self, event, data, to=None):
        self.emitted.append((event, data, to))

    def sleep(self, s):
        raise _StopLoop


class _OneShotRedis:
    def __init__(self, entries):
        self.entries, self.calls = entries, 0

    def xread(self, streams, count, block):
        self.calls += 1
        if self.calls == 1:
            return [("ids:alerts", self.entries)]
        raise RuntimeError("end of test")


def test_bridge_emits_only_to_authenticated_room(monkeypatch):
    monkeypatch.setattr(redis_alert_bridge, "get_ip_location", lambda ip: {"country": "X"})
    sio = _FakeSocketIO()
    r = _OneShotRedis([("1-0", {"data": json.dumps({"src_ip": "1.1.1.1"})})])
    with pytest.raises(_StopLoop):
        redis_alert_bridge.start_redis_alert_bridge(sio, r)
    assert sio.emitted == [("new_alert", {"src_ip": "1.1.1.1", "location": {"country": "X"}},
                            redis_alert_bridge.ALERT_ROOM)]


def test_bridge_skips_malformed_and_non_object_entries(monkeypatch):
    monkeypatch.setattr(redis_alert_bridge, "get_ip_location", lambda ip: None)
    sio = _FakeSocketIO()
    r = _OneShotRedis([("1-0", {"data": "not json"}), ("2-0", {"data": "[1,2]"}),
                       ("3-0", {}), ("4-0", {"data": json.dumps({"src_ip": "1.1.1.1"})})])
    with pytest.raises(_StopLoop):
        redis_alert_bridge.start_redis_alert_bridge(sio, r)
    assert len(sio.emitted) == 1


def test_bridge_survives_geoip_failure(monkeypatch):
    def boom(ip):
        raise OSError("no mmdb")
    monkeypatch.setattr(redis_alert_bridge, "get_ip_location", boom)
    sio = _FakeSocketIO()
    r = _OneShotRedis([("1-0", {"data": json.dumps({"src_ip": "1.1.1.1"})})])
    with pytest.raises(_StopLoop):
        redis_alert_bridge.start_redis_alert_bridge(sio, r)
    assert sio.emitted[0][1]["location"] is None


# ---------------------------------------------------------------- socket auth (logic only)

def _socket_authorized():
    """Import main.socket_authorized without running main's app setup side effects."""
    import ast
    src = open(os.path.join(os.path.dirname(__file__), "..", "main.py"), encoding="utf-8").read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == "socket_authorized")
    ns = {"hmac": __import__("hmac")}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "main.py", "exec"), ns)
    return ns["socket_authorized"]


@pytest.mark.parametrize("auth,ok", [
    ({"token": "s3cret"}, True),
    ({"token": "wrong"}, False),
    ({}, False),
    (None, False),
    ({"token": 123}, False),
    ("s3cret", False),
])
def test_socket_auth_with_token(auth, ok):
    assert _socket_authorized()(auth, "s3cret") is ok


def test_socket_auth_open_when_no_token_configured():
    assert _socket_authorized()(None, "") is True