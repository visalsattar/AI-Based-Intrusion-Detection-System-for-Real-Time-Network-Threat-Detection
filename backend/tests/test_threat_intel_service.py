"""threat_intel_service.py owns the private/public IP gate; routes.py trusts it completely."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
import threat_intel_service as tis  # noqa: E402


class ExplodingRedis:
    """Any call means the privacy check happened too late -- a cache read/write or network
    call was attempted for an address that should never leave this process."""
    def get(self, key): raise AssertionError("private IPs must never trigger a cache read")
    def set(self, *a, **k): raise AssertionError("private IPs must never be cached")


@pytest.mark.parametrize("ip", ["192.168.1.9", "10.0.0.4", "172.16.0.5", "127.0.0.1", "::1"])
def test_private_and_loopback_ips_short_circuit(ip, monkeypatch):
    monkeypatch.setattr(tis.requests, "get", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("private IP must never reach the AbuseIPDB API")))
    r = tis.lookup_ip(ip, redis_client=ExplodingRedis())
    assert r["status"] == "private" and r["abuse_score"] is None


def test_public_ip_without_a_key_is_not_configured(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    assert tis.lookup_ip("8.8.4.4", redis_client=None)["status"] == "not_configured"


def test_public_ip_uses_env_key_over_redis_stored_key(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "env-key")
    seen = {}

    def fake_get(url, headers=None, params=None, timeout=None):
        seen["key"] = headers["Key"]
        class R:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return {"data": {"abuseConfidenceScore": 10, "totalReports": 1}}
        return R()

    monkeypatch.setattr(tis.requests, "get", fake_get)

    class Redis:
        def get(self, k): return None
        def set(self, *a, **k): pass

    tis.lookup_ip("8.8.4.4", redis_client=Redis())
    assert seen["key"] == "env-key"


def test_cache_hit_skips_the_network_call(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    cached = {"ip": "8.8.4.4", "abuse_score": 77, "reports": 3}

    class Redis:
        def get(self, k): return json.dumps(cached)

    monkeypatch.setattr(tis.requests, "get", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("cache hit must not call the network")))
    r = tis.lookup_ip("8.8.4.4", redis_client=Redis())
    assert r["status"] == "cached" and r["abuse_score"] == 77


def test_rate_limit_is_surfaced_not_raised(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")

    class R:
        status_code = 429
    monkeypatch.setattr(tis.requests, "get", lambda *a, **k: R())

    class Redis:
        def get(self, k): return None

    assert tis.lookup_ip("8.8.4.4", redis_client=Redis())["status"] == "rate_limited"


def test_lookup_many_caps_at_max_lookups(monkeypatch):
    calls = []
    monkeypatch.setattr(tis, "lookup_ip", lambda ip, redis_client=None: (calls.append(ip), {"ip": ip})[1])
    ips = [f"8.8.4.{i}" for i in range(30)]
    out = tis.lookup_many(ips, redis_client=None, max_lookups=25)
    assert len(out) == 25 and calls == ips[:25]
