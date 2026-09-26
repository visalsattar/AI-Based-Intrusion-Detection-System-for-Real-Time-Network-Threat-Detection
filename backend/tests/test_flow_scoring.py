"""
Model-free tests for the live pipeline's flow lifecycle, alert cooldown, Redis trimming
and IPS guardrails.

They build RealTimeIDSPipeline with object.__new__ and stub the autoencoder/scaler, so they
need neither TensorFlow nor the trained models -> they run (not skip) in CI on a clean
checkout. test_inference.py keeps covering the real-model paths.
"""
import json
import subprocess
import time

import numpy as np
import pytest
from scapy.all import Ether, IP, TCP, UDP

import ids_pipeline
from feature_order import FEATURE_ORDER
from ids_pipeline import RealTimeIDSPipeline
from stubs import RecordingRedis, StubAE, StubScaler, make_pipeline  # noqa: F401


@pytest.fixture
def pipe():
    return make_pipeline()


def tcp(src, dst, sport, dport, flags):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


def feed(p, *pkts):
    for pk in pkts:
        p.packet_callback(pk)


# ------------------------------------------------------------------ flow lifecycle

def test_finished_flow_is_scored_exactly_once(pipe):
    """Regression: a merged-in duplicate block used to append every finished flow twice."""
    feed(pipe, tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"),
               tcp("10.0.0.5", "8.8.4.4", 80, 4444, "SA"),
               tcp("8.8.4.4", "10.0.0.5", 4444, 80, "FA"))
    pipe._inference_batch()
    assert pipe.autoencoder.rows_seen == 1, "flow was fed to the autoencoder more than once"
    assert pipe.flow_tracker == {}, "scored flow must be dropped so it is never re-scored"


def test_unfinished_flow_is_not_scored(pipe):
    feed(pipe, tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"),
               tcp("8.8.4.4", "10.0.0.5", 4444, 80, "A"))
    pipe._inference_batch()
    assert pipe.autoencoder.rows_seen == 0
    assert len(pipe.flow_tracker) == 1


def test_idle_flow_is_scored_without_any_new_packet(pipe):
    """The ticker path: no packet arrives, the flow still gets scored once it ages out."""
    feed(pipe, tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"))
    from datetime import datetime, timedelta
    for f in pipe.flow_tracker.values():
        f["last_seen"] = datetime.now() - timedelta(seconds=pipe.flow_idle_timeout + 1)
    pipe.batch_interval = 0.0
    pipe._tick_once()
    assert pipe.autoencoder.rows_seen == 1
    assert pipe.flow_tracker == {}


def test_packet_cap_marks_flow_done(pipe):
    pipe.max_packets_per_flow = 5
    feed(pipe, *[tcp("8.8.4.4", "10.0.0.5", 4444, 80, "A") for _ in range(5)])
    pipe._inference_batch()
    assert pipe.autoencoder.rows_seen == 1


# ------------------------------------------------------------------ alerting

def _finish_flow(p, src="8.8.4.4", dst="10.0.0.5", sport=4444, dport=80):
    feed(p, tcp(src, dst, sport, dport, "S"), tcp(src, dst, sport, dport, "FA"))
    p._inference_batch()


def test_alert_stream_is_trimmed(pipe):
    _finish_flow(pipe)
    stream, _, kw = pipe.redis_client.calls[0]
    assert stream == "ids:alerts"
    assert kw.get("maxlen") == 5000 and kw.get("approximate") is True


def test_port_scan_is_deduplicated_across_destination_ports(pipe):
    """Cooldown key must not include dport, or a scan raises one alert per port."""
    for port in range(1000, 1010):
        _finish_flow(pipe, dport=port, sport=5000 + port)
    alerts = pipe.redis_client.alerts()
    assert len(alerts) == 1
    # 9 later flows were swallowed; the next alert (after cooldown) will report that
    assert pipe._last_alert[("8.8.4.4", alerts[0]["severity"])][1] == 9


def test_escalation_bypasses_cooldown_and_reports_suppressed_count(pipe):
    _finish_flow(pipe, dport=81, sport=6001)                 # first alert
    pipe.autoencoder.delta = 0.9                             # different score, same severity band
    _finish_flow(pipe, dport=82, sport=6002)                 # suppressed
    k = next(iter(pipe._last_alert))
    ts, n = pipe._last_alert[k]
    pipe._last_alert[k] = (ts - pipe.alert_cooldown - 1, n)  # cooldown elapsed
    _finish_flow(pipe, dport=83, sport=6003)
    alerts = pipe.redis_client.alerts()
    assert len(alerts) == 2 and alerts[1]["suppressed_since_last"] == 1


# ------------------------------------------------------------------ IPS guardrails

@pytest.fixture
def fw(monkeypatch):
    """Capture firewall commands instead of running them."""
    cmds = []

    def fake_run(cmd, capture_output=True, timeout=10):
        cmds.append(cmd)
        rc = 1 if "-C" in cmd else 0          # iptables -C: rule not present yet
        return subprocess.CompletedProcess(cmd, rc, b"", b"")

    monkeypatch.setattr(ids_pipeline.subprocess, "run", fake_run)
    monkeypatch.setattr(ids_pipeline.platform, "system", lambda: "Linux")
    return cmds


def _attack(p, syn_first=True, src="8.8.4.4", dst="10.0.0.5"):
    p._settings_cache = {"autoBlock": True}
    first = "S" if syn_first else "A"
    feed(p, tcp(src, dst, 4444, 80, first), tcp(src, dst, 4444, 80, "FA"))
    p._inference_batch()


def test_inbound_syn_from_public_ip_is_blocked_with_ttl(pipe, fw):
    _attack(pipe)
    assert ["iptables", "-I", "INPUT", "1", "-s", "8.8.4.4", "-j", "DROP"] in fw
    assert "8.8.4.4" in pipe._blocked


def test_no_block_when_initiator_not_proven(pipe, fw):
    _attack(pipe, syn_first=False)
    assert not any("-I" in c for c in fw) and pipe._blocked == {}


def test_no_block_for_outbound_flow(pipe, fw):
    """Sensor host is 10.0.0.5: a flow it opened toward a public server must never block it."""
    _attack(pipe, src="10.0.0.5", dst="8.8.4.4")
    assert pipe._blocked == {}


def test_no_block_for_udp(pipe, fw):
    pipe._settings_cache = {"autoBlock": True}
    feed(pipe, IP(src="8.8.4.4", dst="10.0.0.5") / UDP(sport=53, dport=5353))
    pipe.flow_tracker[next(iter(pipe.flow_tracker))]["done"] = True
    pipe._done.update(pipe.flow_tracker)
    pipe._inference_batch()
    assert pipe._blocked == {}


def test_private_source_is_never_blocked(pipe, fw):
    _attack(pipe, src="192.168.1.77")
    assert pipe._blocked == {} and not any("-I" in c for c in fw)


def test_whitelist_wins(pipe, fw):
    pipe._whitelist = {"8.8.4.4"}
    _attack(pipe)
    assert pipe._blocked == {}


def test_blocks_expire_and_rules_are_removed(pipe, fw):
    _attack(pipe)
    pipe._blocked["8.8.4.4"] = time.time() - 1
    pipe._expire_blocks()
    assert ["iptables", "-D", "INPUT", "-s", "8.8.4.4", "-j", "DROP"] in fw
    assert pipe._blocked == {}


def test_windows_block_uses_argv_not_a_shell(pipe, monkeypatch):
    cmds = []
    monkeypatch.setattr(ids_pipeline.subprocess, "run",
                        lambda cmd, **kw: (cmds.append(cmd), subprocess.CompletedProcess(cmd, 0, b"", b""))[1])
    monkeypatch.setattr(ids_pipeline.platform, "system", lambda: "Windows")
    monkeypatch.setattr(ids_pipeline.os, "system",
                        lambda *_: pytest.fail("os.system must not be used"), raising=False)
    assert ids_pipeline.block_ip("8.8.4.4") is True
    assert isinstance(cmds[0], list) and "remoteip=8.8.4.4" in cmds[0]


# ------------------------------------------------------------------ capture filter / redis config

def test_capture_filter_excludes_own_services(monkeypatch):
    monkeypatch.setenv("REDIS_PORT", "6380")
    monkeypatch.setenv("PORT", "5000")
    monkeypatch.setenv("IDS_EXCLUDE_PORTS", "8080, x ,9000")
    f = RealTimeIDSPipeline._capture_filter()
    for port in (5000, 6380, 8080, 9000):
        assert f"not port {port}" in f
    assert f.startswith("(tcp or udp)")


def test_make_redis_reads_host_port_password(monkeypatch):
    from redis_util import make_redis
    monkeypatch.setenv("REDIS_HOST", "example.invalid")
    monkeypatch.setenv("REDIS_PORT", "6380")
    monkeypatch.setenv("REDIS_PASSWORD", "s3cret")
    kw = make_redis().connection_pool.connection_kwargs
    assert (kw["host"], kw["port"], kw["password"]) == ("example.invalid", 6380, "s3cret")


# ------------------------------------------------------------------ feature extraction semantics

def idx(name):
    return FEATURE_ORDER.index(name)


def test_feature_table_is_78_unique_names():
    assert len(FEATURE_ORDER) == 78 and len(set(FEATURE_ORDER)) == 78


def test_live_feature_coverage_explicitly_discloses_unsupported_fields(pipe):
    assert len(pipe.UNSUPPORTED_LIVE_FEATURES) == 14
    assert pipe._live_feature_coverage() == pytest.approx(64 / 78)


def _eth(pkt):
    return Ether() / pkt


def test_extractor_puts_values_under_the_right_names_and_uses_payload_bytes(pipe):
    """
    Ethernet frames, as a real NIC delivers them. CICFlowMeter measures PAYLOAD bytes
    (BasicFlow.addPacket -> getPayloadBytes()); len(frame) would add 14 (Ethernet) + 40 (IP/TCP)
    to every packet, so a bare SYN would read 54 instead of 0.
    """
    c, s = "10.0.0.20", "93.184.216.34"
    feed(pipe,
         _eth(IP(src=c, dst=s) / TCP(sport=51000, dport=443, flags="S")),
         _eth(IP(src=s, dst=c) / TCP(sport=443, dport=51000, flags="SA")),
         _eth(IP(src=c, dst=s) / TCP(sport=51000, dport=443, flags="PA") / ("x" * 100)),
         _eth(IP(src=s, dst=c) / TCP(sport=443, dport=51000, flags="PA") / ("y" * 300)))
    f = pipe._extract_flow_features(next(iter(pipe.flow_tracker)))
    g = lambda name: float(f[idx(name)])

    assert g("Destination Port") == 443
    assert (g("Total Fwd Packets"), g("Total Backward Packets")) == (2, 2)
    assert (g("Total Length of Fwd Packets"), g("Total Length of Bwd Packets")) == (100, 300)
    assert (g("Fwd Packet Length Max"), g("Fwd Packet Length Min"), g("Fwd Packet Length Mean")) == (100, 0, 50)
    assert (g("Bwd Packet Length Max"), g("Bwd Packet Length Min"), g("Bwd Packet Length Mean")) == (300, 0, 150)
    assert (g("Min Packet Length"), g("Max Packet Length"), g("Packet Length Mean")) == (0, 300, 100)
    assert g("act_data_pkt_fwd") == 1, "the bare SYN must not count as a data packet"
    assert g("SYN Flag Count") == 1 and g("ACK Flag Count") == 1 and g("FIN Flag Count") == 0
    assert g("Init_Win_bytes_forward") == 8192
    assert g("Fwd Header Length") == 80 and g("Fwd Header Length.1") == 80    # 2 packets x (IP 20 + TCP 20)
    # Flow Bytes/s is payload / duration; Flow Duration is in microseconds
    assert g("Flow Bytes/s") * g("Flow Duration") / 1e6 == pytest.approx(400)
    assert f.shape == (78,) and np.isfinite(f).all()


def test_ethernet_padding_is_not_counted_as_payload(pipe):
    """A minimum-size frame carries 6 padding bytes that Scapy reports inside the TCP payload."""
    syn = Ether() / IP(src="8.8.4.4", dst="10.0.0.5") / TCP(sport=4444, dport=80, flags="S")
    padded = Ether(bytes(syn) + b"\x00" * 6)
    assert len(padded[TCP].payload) == 6              # what a naive len(payload) would say
    feed(pipe, padded)
    f = pipe._extract_flow_features(next(iter(pipe.flow_tracker)))
    assert f[idx("Total Length of Fwd Packets")] == 0 and f[idx("act_data_pkt_fwd")] == 0


# ------------------------------------------------------------------ flush / dump

def test_flush_scores_finished_flows_without_touching_private_state(pipe):
    feed(pipe, tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"), tcp("8.8.4.4", "10.0.0.5", 4444, 80, "FA"))
    pipe.flush()
    assert pipe.autoencoder.rows_seen == 1 and pipe.flow_tracker == {}


def test_feature_dump_writes_raw_features_with_real_column_names(pipe, tmp_path):
    import csv
    pipe._dump_path = str(tmp_path / "live.csv")
    _finish_flow(pipe)
    rows = list(csv.DictReader(open(pipe._dump_path)))
    assert len(rows) == 1
    assert set(FEATURE_ORDER) <= set(rows[0]) and {"recon_error", "rf_prob", "src_ip", "feature_coverage", "evidence_origin"} <= set(rows[0])
    assert rows[0]["src_ip"] == "8.8.4.4" and rows[0]["rf_prob"] == ""      # RF absent -> blank


def test_unvalidated_ae_only_result_is_suppressed(pipe):
    pipe.ae_only_alerting_validated = False
    _finish_flow(pipe)
    assert pipe.redis_client.alerts() == []


def test_broken_dump_disables_itself_and_never_breaks_scoring(pipe, tmp_path):
    pipe._dump_path = str(tmp_path)              # a directory: open() will fail
    _finish_flow(pipe)
    assert pipe._dump_path is None
    assert len(pipe.redis_client.alerts()) == 1  # the alert still went out
