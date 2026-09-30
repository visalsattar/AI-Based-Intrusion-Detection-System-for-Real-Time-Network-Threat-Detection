"""
Tests for the legacy AbuseIPDB-key migration, /api/health, and the mutation guard/settings save.

Several tests here began as strict xfails that reproduced confirmed bugs (corrupt-JSON retry loop,
health 200 while Redis down, DNS rebinding, settings clobbered on a transient read failure).
They now pass against the fixed routes.py and act as regression tests.

Assumes backend/ is importable as top-level modules (same as the existing suite's conftest).
Requires: pip install fakeredis
"""
import json
import os
import sys

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (_BACKEND, os.path.join(_BACKEND, "src")):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest
from flask import Flask

import routes

fakeredis = pytest.importorskip("fakeredis")


# ---------------------------------------------------------------- fixtures / helpers

@pytest.fixture(params=[True, False], ids=["str-client", "bytes-client"])
def r(request):
    # Exercise both decode_responses modes: prod client config must not change behaviour.
    return fakeredis.FakeRedis(decode_responses=request.param)


@pytest.fixture(autouse=True)
def _no_token(monkeypatch):
    monkeypatch.delenv("IDS_API_TOKEN", raising=False)
    monkeypatch.delenv("IDS_ALLOWED_ORIGINS", raising=False)


class Sleeps:
    def __init__(self):
        self.calls = []

    def __call__(self, seconds):
        self.calls.append(seconds)


class DownRedis:
    """Stands in for a lazy redis client whose server refuses connections."""
    def ping(self):
        raise ConnectionError("Connection refused")

    def get(self, *_a, **_k):
        raise ConnectionError("Connection refused")


def client_for(redis_client):
    app = Flask(__name__)
    app.testing = True
    routes.register_routes(app, redis_client)
    return app.test_client()


def stored(r):
    return json.loads(r.get("ids:settings"))


# ---------------------------------------------------------------- migrate_legacy_settings

def test_migration_strips_key_and_preserves_other_settings(r):
    r.set("ids:settings", json.dumps({"abuseIPDBKey": "secret", "sensitivity": "high"}))
    assert routes.migrate_legacy_settings(r) is True
    assert stored(r) == {"sensitivity": "high"}


def test_migration_noop_when_no_legacy_key(r):
    r.set("ids:settings", json.dumps({"sensitivity": "low"}))
    assert routes.migrate_legacy_settings(r) is False
    assert stored(r) == {"sensitivity": "low"}


def test_migration_noop_when_settings_absent(r):
    assert routes.migrate_legacy_settings(r) is False
    assert r.get("ids:settings") is None


def test_migration_noop_on_non_dict_json(r):
    r.set("ids:settings", json.dumps([1, 2, 3]))
    assert routes.migrate_legacy_settings(r) is False


def test_migration_is_idempotent(r):
    r.set("ids:settings", json.dumps({"abuseIPDBKey": "secret"}))
    assert routes.migrate_legacy_settings(r) is True
    assert routes.migrate_legacy_settings(r) is False
    assert stored(r) == {}


# ---------------------------------------------------------------- migrate_legacy_settings_until_done

def test_until_done_does_not_sleep_on_first_success(r):
    sleeps = Sleeps()
    routes.migrate_legacy_settings_until_done(r, sleep=sleeps, interval=5)
    assert sleeps.calls == []


def test_until_done_retries_with_interval_then_completes(r, monkeypatch):
    r.set("ids:settings", json.dumps({"abuseIPDBKey": "secret", "sound": False}))
    real = routes.migrate_legacy_settings
    attempts = {"n": 0}

    def flaky(client):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConnectionError("down")
        return real(client)

    monkeypatch.setattr(routes, "migrate_legacy_settings", flaky)
    sleeps = Sleeps()
    routes.migrate_legacy_settings_until_done(r, sleep=sleeps, interval=5)

    assert attempts["n"] == 3
    assert sleeps.calls == [5, 5]          # slept between attempts, never busy-spun
    assert stored(r) == {"sound": False}


def test_until_done_gives_up_on_corrupt_json(r):
    r.set("ids:settings", "{not json")
    sleeps = Sleeps()

    def bounded(seconds):
        sleeps(seconds)
        if len(sleeps.calls) >= 3:
            raise RuntimeError("still retrying a non-transient error")

    routes.migrate_legacy_settings_until_done(r, sleep=bounded, interval=1)


# ---------------------------------------------------------------- /api/health

def test_health_reports_redis_connected(r):
    body = client_for(r).get("/api/health").get_json()
    assert body["redis"] == "connected"


def test_health_reports_redis_disconnected_without_raising():
    resp = client_for(DownRedis()).get("/api/health")
    assert resp.get_json()["redis"] == "disconnected"


def test_health_returns_503_when_redis_down():
    resp = client_for(DownRedis()).get("/api/health")
    assert resp.status_code == 503
    assert resp.get_json()["status"] == "degraded"


def test_health_returns_200_when_redis_up(r):
    resp = client_for(r).get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "running"


# ---------------------------------------------------------------- mutation guard

def test_cross_origin_post_rejected(r):
    resp = client_for(r).post("/api/save-settings", json={"autoBlock": True},
                              headers={"Origin": "http://evil.example"})
    assert resp.status_code == 403


def test_token_required_when_configured(r, monkeypatch):
    monkeypatch.setenv("IDS_API_TOKEN", "t0ken")
    c = client_for(r)
    assert c.post("/api/save-settings", json={"sound": False}).status_code == 401
    ok = c.post("/api/save-settings", json={"sound": False},
                headers={"Authorization": "Bearer t0ken"})
    assert ok.status_code == 200


def test_dns_rebinding_origin_rejected(r):
    resp = client_for(r).post("/api/save-settings", json={"autoBlock": True},
                              headers={"Origin": "http://evil.example:5000"},
                              base_url="http://evil.example:5000")
    assert resp.status_code == 403
    assert r.get("ids:settings") is None          # nothing was written


def test_dns_rebinding_blocks_reads_too(r):
    resp = client_for(r).get("/api/history", base_url="http://evil.example:5000")
    assert resp.status_code == 403


@pytest.mark.parametrize("host", ["localhost:5000", "127.0.0.1:5000", "[::1]:5000"])
def test_loopback_hosts_allowed(r, host):
    assert client_for(r).get("/api/history", base_url=f"http://{host}").status_code == 200


def test_extra_host_allowed_via_env(r, monkeypatch):
    monkeypatch.setenv("IDS_ALLOWED_HOSTS", "192.168.1.50")
    assert client_for(r).get("/api/history", base_url="http://192.168.1.50:5000").status_code == 200


# ---------------------------------------------------------------- save-settings

def test_invalid_stored_value_falls_back_to_default(r):
    r.set("ids:settings", json.dumps({"criticalThreshold": "0.9", "sensitivity": "high"}))
    body = client_for(r).get("/api/settings").get_json()
    assert body["criticalThreshold"] == routes.DEFAULT_SETTINGS["criticalThreshold"]
    assert body["sensitivity"] == "high"


def test_save_with_invalid_stored_threshold_does_not_500(r):
    r.set("ids:settings", json.dumps({"criticalThreshold": "0.9"}))
    resp = client_for(r).post("/api/save-settings", json={"sound": False})
    assert resp.status_code == 200


def test_save_does_not_clobber_settings_on_transient_read_failure(r, monkeypatch):
    r.set("ids:settings", json.dumps({**routes.DEFAULT_SETTINGS, "sensitivity": "high", "autoBlock": True}))
    real_get = r.get
    state = {"fail": True}

    def blip_get(key):
        if state["fail"]:
            state["fail"] = False
            raise ConnectionError("blip")
        return real_get(key)

    monkeypatch.setattr(r, "get", blip_get)
    resp = client_for(r).post("/api/save-settings", json={"sound": False})
    assert resp.status_code == 503
    saved = json.loads(real_get("ids:settings"))
    assert saved["sensitivity"] == "high" and saved["autoBlock"] is True