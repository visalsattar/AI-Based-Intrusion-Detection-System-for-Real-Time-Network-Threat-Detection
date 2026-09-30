"""Round-2 hardening tests: startup auth gate and capture filter scope."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ids_pipeline import RealTimeIDSPipeline  # noqa: E402
from routes import startup_auth_error  # noqa: E402


class TestStartupAuthGate:
    @pytest.mark.parametrize("bind", ["127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.53"])
    def test_loopback_without_token_is_allowed(self, bind):
        assert startup_auth_error(bind, "", False) is None

    @pytest.mark.parametrize("bind", ["0.0.0.0", "192.168.1.10", "::", "eth0-typo"])
    def test_exposed_without_token_refuses(self, bind):
        assert "Refusing to start" in startup_auth_error(bind, "", False)

    def test_exposed_with_token_is_allowed(self):
        assert startup_auth_error("0.0.0.0", "s3cret", False) is None

    def test_explicit_opt_out_is_allowed(self):
        assert startup_auth_error("0.0.0.0", "", True) is None


class TestCaptureFilterScope:
    def test_plumbing_ports_excluded_only_for_local_hosts(self, monkeypatch):
        monkeypatch.setenv("REDIS_PORT", "6379")
        monkeypatch.setenv("PORT", "5000")
        monkeypatch.delenv("IDS_EXCLUDE_PORTS", raising=False)
        bpf = RealTimeIDSPipeline._capture_filter(local_ips={"10.0.0.5"})
        assert bpf == ("(tcp or udp) and not (port 5000 and (host 10.0.0.5))"
                       " and not (port 6379 and (host 10.0.0.5))")
        assert " and not port 5000" not in bpf      # no global blind spot

    def test_multiple_local_ips_and_extra_ports(self, monkeypatch):
        monkeypatch.setenv("REDIS_PORT", "6380")
        monkeypatch.setenv("PORT", "5000")
        monkeypatch.setenv("IDS_EXCLUDE_PORTS", "22, x")
        bpf = RealTimeIDSPipeline._capture_filter(local_ips={"10.0.0.5", "127.0.0.1"})
        assert "not (port 22 and (host 10.0.0.5 or host 127.0.0.1))" in bpf
        assert "port 6380" in bpf and "port 6379" not in bpf

    def test_unknown_local_ips_falls_back_loudly(self, monkeypatch):
        monkeypatch.setenv("REDIS_PORT", "6379")
        monkeypatch.setenv("PORT", "5000")
        monkeypatch.delenv("IDS_EXCLUDE_PORTS", raising=False)
        assert RealTimeIDSPipeline._capture_filter(local_ips=set()).endswith(
            "and not port 5000 and not port 6379")

    def test_filter_compiles_as_bpf(self):
        """Real libpcap syntax check; skipped where no compiler is available."""
        scapy_arch = pytest.importorskip("scapy.arch.common")
        compile_filter = getattr(scapy_arch, "compile_filter", None)
        if compile_filter is None:
            pytest.skip("scapy compile_filter unavailable")
        bpf = RealTimeIDSPipeline._capture_filter(local_ips={"10.0.0.5", "127.0.0.1"})
        try:
            compile_filter(bpf)
        except Exception as e:  # missing tcpdump/libpcap on this machine
            if "tcpdump" in str(e).lower() or "libpcap" in str(e).lower():
                pytest.skip(str(e))
            raise