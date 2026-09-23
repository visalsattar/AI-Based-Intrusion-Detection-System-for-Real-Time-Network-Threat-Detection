"""
Security regression tests for routes.py: origin guard, optional bearer token, settings
allow-list/validation, no secret echo, no AbuseIPDB quota burned on private IPs.
Needs only Flask -- no Redis server, no models.
"""
import json
import os
import sys

import pytest
from flask import Flask

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import routes  # noqa: E402


class FakeRedis:
    def __init__(self):
        self.kv, self.alerts = {}, []

    def get(self, k): return self.kv.get(k)
    def set(self, k, v): self.kv[k] = v
    def delete(self, k):
        self.kv.pop(k, None)
        self.alerts.clear()
    def xrevrange(self, stream, count=200):
        return [(str(i), {"data": json.dumps(a)}) for i, a in enumerate(self.alerts[:count])]
    def xlen(self, stream): return len(self.alerts)


@pytest.fixture
def env():
    r = FakeRedis()
    app = Flask(__name__)
    routes.register_routes(app, r)
    return app.test_client(), r


GOOD_KEY = "a" * 40


def test_cross_site_origin_cannot_change_settings(env):
    c, r = env
    resp = c.post("/api/save-settings", json={"autoBlock": True}, headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403 and "ids:settings" not in r.kv


def test_cross_site_origin_cannot_wipe_alert_log(env):
    c, r = env
    r.alerts.append({"src_ip": "8.8.8.8"})
    assert c.delete("/api/history", headers={"Origin": "https://evil.example"}).status_code == 403
    assert r.alerts, "alert log was wiped by a foreign origin"


def test_same_origin_and_dev_server_origin_are_allowed(env):
    c, _ = env
    assert c.post("/api/save-settings", json={"sound": False},
                  headers={"Origin": "http://localhost"}).status_code == 200      # same host as test client
    assert c.post("/api/save-settings", json={"sound": False},
                  headers={"Origin": "http://localhost:3000"}).status_code == 200  # CRA dev server


def test_token_required_when_configured(env, monkeypatch):
    c, _ = env
    monkeypatch.setenv("IDS_API_TOKEN", "t0ken")
    assert c.post("/api/save-settings", json={"sound": True}).status_code == 401
    assert c.post("/api/save-settings", json={"sound": True},
                  headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.post("/api/save-settings", json={"sound": True},
                  headers={"Authorization": "Bearer t0ken"}).status_code == 200
    assert c.get("/api/settings").status_code == 200        # reads stay open


def test_unknown_keys_are_dropped_not_persisted(env):
    c, r = env
    c.post("/api/save-settings", json={"sound": False, "abuseIPDBKeySet": True, "__proto__": {"x": 1}})
    saved = json.loads(r.kv["ids:settings"])
    assert "abuseIPDBKeySet" not in saved and "__proto__" not in saved


@pytest.mark.parametrize("payload", [
    {"criticalThreshold": -1},           # would make every alert CRITICAL
    {"criticalThreshold": "0.9"},
    {"highThreshold": 0.9, "criticalThreshold": 0.9},
    {"flowTimeout": 0},
    {"autoBlock": "yes"},
    {"sensitivity": "extreme"},
    {"abuseIPDBKey": "not a key!"},
])
def test_invalid_settings_rejected(env, payload):
    c, r = env
    resp = c.post("/api/save-settings", json=payload)
    assert resp.status_code == 400 and "ids:settings" not in r.kv


def test_non_object_body_rejected(env):
    c, _ = env
    assert c.post("/api/save-settings", data="[1,2]", content_type="application/json").status_code == 400


def test_api_key_is_never_echoed_and_blank_keeps_saved_key(env):
    c, r = env
    assert c.post("/api/save-settings", json={"abuseIPDBKey": GOOD_KEY}).status_code == 200
    got = c.get("/api/settings").get_json()
    assert got["abuseIPDBKey"] == "" and got["abuseIPDBKeySet"] is True
    assert c.post("/api/save-settings", json={"abuseIPDBKey": "", "sound": False}).status_code == 200
    assert json.loads(r.kv["ids:settings"])["abuseIPDBKey"] == GOOD_KEY


def test_default_settings_contain_no_secret():
    assert routes.DEFAULT_SETTINGS["abuseIPDBKey"] == ""


def test_threat_intel_reports_each_ips_real_status(env, monkeypatch):
    """
    routes.py does no privacy filtering of its own -- threat_intel_service.lookup_ip already
    returns status='private' for RFC1918/loopback addresses without a cache read or network call
    (see test_threat_intel_service.py). This only checks routes.py passes that status through
    to the JSON response unchanged.
    """
    c, r = env
    ips = ("192.168.1.9", "10.0.0.4", "127.0.0.1", "8.8.4.4")
    r.alerts += [{"src_ip": ip, "severity": "HIGH", "timestamp": 1} for ip in ips]
    asked = []

    def fake_lookup_many(ip_list, redis_client=None):
        asked.extend(ip_list)
        return [{"ip": ip, "status": "private" if ip.startswith(("192.168.", "10.", "127."))
                else "not_configured"} for ip in ip_list]

    monkeypatch.setattr(routes.threat_intel_service, "lookup_many", fake_lookup_many)
    data = c.get("/api/threat-intel").get_json()
    assert sorted(asked) == sorted(ips), "every source IP must reach threat_intel_service"
    status = {rec["ip"]: rec["intel_status"] for rec in data["records"]}
    assert status["192.168.1.9"] == "private" and status["8.8.4.4"] == "not_configured"
