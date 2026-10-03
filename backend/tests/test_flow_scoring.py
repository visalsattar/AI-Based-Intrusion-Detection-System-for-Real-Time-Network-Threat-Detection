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


# - flow lifecycle

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


# - alerting

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


# - IPS guardrails

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
    """Inbound attack flow. With syn_first=True the initiator completes a real
    3-way handshake (SYN -> our SYN-ACK -> ACK of synack_seq+1), which AutoBlock
    now requires: a bare SYN is spoofable and must never get an IP blocked."""
    p._settings_cache = {"autoBlock": True}
    if syn_first:
        feed(p,
             IP(src=src, dst=dst) / TCP(sport=4444, dport=80, flags="S", seq=1000),
             IP(src=dst, dst=src) / TCP(sport=80, dport=4444, flags="SA", seq=5000, ack=1001),
             IP(src=src, dst=dst) / TCP(sport=4444, dport=80, flags="A", seq=1001, ack=5001),
             IP(src=src, dst=dst) / TCP(sport=4444, dport=80, flags="FA", seq=1001, ack=5001))
    else:
        feed(p, tcp(src, dst, 4444, 80, "A"), tcp(src, dst, 4444, 80, "FA"))
    p._inference_batch()


def test_inbound_handshake_from_public_ip_is_blocked_with_ttl(pipe, fw):
    _attack(pipe)
    assert [
        "iptables", "-I", "INPUT", "1", "-s", "8.8.4.4",
        "-m", "comment", "--comment", "IDS-AUTOBLOCK", "-j", "DROP"
    ] in fw
    
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
    assert [
        "iptables", "-D", "INPUT", "-s", "8.8.4.4",
        "-m", "comment", "--comment", "IDS-AUTOBLOCK", "-j", "DROP"
    ] in fw
    assert pipe._blocked == {}


def test_windows_block_uses_argv_not_a_shell(pipe, monkeypatch):
    cmds = []

    monkeypatch.setattr(
        ids_pipeline.subprocess,
        "run",
        lambda cmd, **kw: (
            cmds.append((cmd, kw)),
            subprocess.CompletedProcess(cmd, 0, b"", b"")
        )[1]
    )

    monkeypatch.setattr(
        ids_pipeline.platform,
        "system",
        lambda: "Windows"
    )

    monkeypatch.setattr(
        ids_pipeline.os,
        "system",
        lambda *_: pytest.fail("os.system must not be used"),
        raising=False
    )

    assert ids_pipeline.block_ip("8.8.4.4") is True

    assert cmds
    assert all(isinstance(cmd, list) for cmd, _ in cmds)
    assert all(kw.get("shell", False) is False for _, kw in cmds)

    assert any(
        "Block_IDS_8.8.4.4" in " ".join(cmd)
        for cmd, _ in cmds
    )

# - capture filter / redis config

def test_capture_filter_excludes_own_services(monkeypatch):
    monkeypatch.setenv("REDIS_PORT", "6380")
    monkeypatch.setenv("PORT", "5000")
    monkeypatch.setenv("IDS_EXCLUDE_PORTS", "8080, x ,9000")
    f = RealTimeIDSPipeline._capture_filter(local_ips={"10.0.0.5"})
    for port in (5000, 6380, 8080, 9000):
        # excluded only when this host is an endpoint...
        assert f"not (port {port} and (host 10.0.0.5))" in f
        # ...never globally (that hid attacks on these ports elsewhere on the LAN)
        assert f"not port {port}" not in f


def test_make_redis_reads_host_port_password(monkeypatch):
    from redis_util import make_redis
    monkeypatch.setenv("REDIS_HOST", "example.invalid")
    monkeypatch.setenv("REDIS_PORT", "6380")
    monkeypatch.setenv("REDIS_PASSWORD", "s3cret")
    kw = make_redis().connection_pool.connection_kwargs
    assert (kw["host"], kw["port"], kw["password"]) == ("example.invalid", 6380, "s3cret")


# - feature extraction semantics

def idx(name):
    return FEATURE_ORDER.index(name)


def test_feature_table_is_78_unique_names():
    assert len(FEATURE_ORDER) == 78 and len(set(FEATURE_ORDER)) == 78




def _eth(pkt):
    return Ether() / pkt


def test_extractor_puts_values_under_the_right_names_and_uses_payload_bytes(pipe):
    """
    Ethernet frames, as a real NIC delivers them. CICFlowMeter measures PAYLOAD bytes
    (BasicFlow.addPacket -> getPayloadBytes()); len(frame) would add 14 (Ethernet) + 40 (IP/TCP)
    to every packet, so a bare SYN would read 54 instead of 0.
    """
    c, s = "10.0.0.20", "93.184.216.34"
    p1 = _eth(IP(src=c, dst=s) / TCP(sport=51000, dport=443, flags="S"))
    p2 = _eth(IP(src=s, dst=c) / TCP(sport=443, dport=51000, flags="SA"))
    p3 = _eth(IP(src=c, dst=s) / TCP(sport=51000, dport=443, flags="PA") / ("x" * 100))
    p4 = _eth(IP(src=s, dst=c) / TCP(sport=443, dport=51000, flags="PA") / ("y" * 300))

    p1.time = 1.0
    p2.time = 1.1
    p3.time = 1.2
    p4.time = 2.0

    feed(pipe, p1, p2, p3, p4)
    f = pipe._extract_flow_features(next(iter(pipe.flow_tracker)))
    g = lambda name: float(f[idx(name)])

    assert g("Destination Port") == 443
    assert (g("Total Fwd Packets"), g("Total Backward Packets")) == (2, 2)
    assert (g("Total Length of Fwd Packets"), g("Total Length of Bwd Packets")) == (100, 300)
    assert (g("Fwd Packet Length Max"), g("Fwd Packet Length Min"), g("Fwd Packet Length Mean")) == (100, 0, 50)
    assert (g("Bwd Packet Length Max"), g("Bwd Packet Length Min"), g("Bwd Packet Length Mean")) == (300, 0, 150)
    assert (g("Min Packet Length"), g("Max Packet Length"), g("Packet Length Mean")) == (0, 300, 80)
    assert g("act_data_pkt_fwd") == 1, "the bare SYN must not count as a data packet"
    # SYN and SYN+ACK are both SYN-bearing packets, so CICFlowMeter-style
    # flag fields count packets rather than converting the field to boolean.
    
    # CICFlowMeter-style flag fields count packets carrying the flag.
    # SA and both PA packets carry ACK, so ACK count is 3.  
    assert g("SYN Flag Count") == 2
    assert g("ACK Flag Count") == 3
    assert g("FIN Flag Count") == 0
    assert g("Init_Win_bytes_forward") == 8192
    assert g("Fwd Header Length") == 40 and g("Fwd Header Length.1") == 40    # 2 packets x 20-byte TCP header
    # Flow Bytes/s is payload / duration; Flow Duration is in microseconds
    assert g("Flow Bytes/s") * g("Flow Duration") / 1e6 == pytest.approx(400)
    assert f.shape == (78,) and np.isfinite(f).all()


def _padded_syn():
    syn = Ether() / IP(src="8.8.4.4", dst="10.0.0.5") / TCP(sport=4444, dport=80, flags="S")
    return Ether(bytes(syn) + b"\x00" * 6)          # 54-byte frame padded to the 60-byte minimum


def test_ethernet_padding_counts_as_payload_like_cicids2017(pipe):
    """CIC's CSV records a padded bare RST+ACK with 6 payload bytes (PortScan rows); match it."""
    feed(pipe, _padded_syn())
    f = pipe._extract_flow_features(next(iter(pipe.flow_tracker)))
    assert f[idx("Total Length of Fwd Packets")] == 6


def test_padding_can_be_excluded(pipe, monkeypatch):
    monkeypatch.setattr(ids_pipeline, "COUNT_ETHERNET_PADDING", False)
    feed(pipe, _padded_syn())
    f = pipe._extract_flow_features(next(iter(pipe.flow_tracker)))
    assert f[idx("Total Length of Fwd Packets")] == 0 and f[idx("act_data_pkt_fwd")] == 0

def test_parity_with_cicids2017_training_data(pipe):
    """
    Pinned against Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (225,745 rows):
    Subflow == Total on 100% of rows; Init_Win_bytes_* == -1 on 14.6% (no window seen).
    """
    c, s = "10.0.0.20", "93.184.216.34"
    p1 = _eth(IP(src=c, dst=s) / UDP(sport=51000, dport=53) / ("q" * 40))
    p2 = _eth(IP(src=s, dst=c) / UDP(sport=53, dport=51000) / ("r" * 120))
    p1.time = 1.0
    p2.time = 1.05
    feed(pipe, p1, p2)
    f = pipe._extract_flow_features(next(iter(pipe.flow_tracker)))
    g = lambda name: float(f[idx(name)])

    # UDP has no TCP window -> CICIDS encodes -1, not 0
    assert g("Init_Win_bytes_forward") == -1
    assert g("Init_Win_bytes_backward") == -1

    # No >1 s gap -> subflow features equal the totals, not 0
    assert g("Subflow Fwd Packets") == g("Total Fwd Packets") == 1
    assert g("Subflow Bwd Packets") == g("Total Backward Packets") == 1
    assert g("Subflow Fwd Bytes") == g("Total Length of Fwd Packets") == 40
    assert g("Subflow Bwd Bytes") == g("Total Length of Bwd Packets") == 120


def test_tcp_flow_without_reply_has_bwd_init_win_minus_one(pipe):
    """One-sided TCP flow: forward window is real, backward was never seen -> -1."""
    feed(pipe, _eth(IP(src="8.8.4.4", dst="10.0.0.5") / TCP(sport=4444, dport=80, flags="S")))
    f = pipe._extract_flow_features(next(iter(pipe.flow_tracker)))
    assert f[idx("Init_Win_bytes_forward")] == 8192
    assert f[idx("Init_Win_bytes_backward")] == -1

# - flush / dump

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


# - 1 Oct 2026 WSL flood run fixes

def test_synack_first_flow_is_attributed_to_the_client_not_the_server(pipe, fw):
    """Capture missed the client's SYN: the first packet seen is the server's SYN-ACK.
    The alert must name the client, and AutoBlock must still require a proven handshake."""
    pipe._settings_cache = {"autoBlock": True}
    server, client = "10.0.0.5", "8.8.4.4"
    feed(pipe,
         IP(src=server, dst=client) / TCP(sport=80, dport=4444, flags="SA", seq=5000, ack=1001),
         IP(src=client, dst=server) / TCP(sport=4444, dport=80, flags="A", seq=1001, ack=5001),
         IP(src=client, dst=server) / TCP(sport=4444, dport=80, flags="FA", seq=1001, ack=5001))
    flow = next(iter(pipe.flow_tracker.values()))
    assert (flow["init_src"], flow["init_dst"], flow["init_dport"]) == (client, server, 80)
    assert flow["init_syn"] is False
    assert [s.fwd for s in flow["packet_list"]] == [False, True, True]
    pipe._inference_batch()
    alerts = pipe.redis_client.alerts()
    assert alerts and alerts[0]["src_ip"] == client
    assert pipe._blocked == {} and not any("-I" in c for c in fw)


class _BinaryRF:
    classes_ = np.array([0, 1])

    def __init__(self, p_attack):
        self.p = p_attack

    def predict_proba(self, x):
        return np.tile([1 - self.p, self.p], (len(x), 1))


@pytest.mark.parametrize("p_attack,expected", [(0.95, "Lab Flood"), (0.10, "Network Anomaly")])
def test_binary_rf_uses_label_map_name_only_when_rf_says_attack(pipe, p_attack, expected):
    pipe.random_forest, pipe._label_map = _BinaryRF(p_attack), {0: "Benign", 1: "Lab Flood"}
    pipe.autoencoder.delta = 0.9                       # AE high -> an alert fires either way
    for i in range(200):                               # 8.8.4.4 is flooding (rate gate)
        pipe._note_new_flow("8.8.4.4", time.time() - i * 0.01)
    feed(pipe, tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"), tcp("8.8.4.4", "10.0.0.5", 4444, 80, "FA"))
    pipe._inference_batch()
    assert pipe.redis_client.alerts()[0]["threat_type"] == expected


class _DyingSniffer:
    """AsyncSniffer stand-in whose session ends at once (e.g. no capture privileges)."""
    starts = 0

    def __init__(self, **kw):
        self.running = False

    def start(self):
        type(self).starts += 1


def test_capture_fails_loudly_when_the_session_keeps_dying(pipe, monkeypatch):
    _DyingSniffer.starts = 0
    monkeypatch.setattr(ids_pipeline, "AsyncSniffer", _DyingSniffer)
    monkeypatch.setattr(pipe, "_ticker", lambda: None)
    monkeypatch.setattr(pipe, "_capture_heartbeat", lambda: None)
    monkeypatch.setattr(pipe, "_worker", lambda: None)
    monkeypatch.setattr(pipe, "_capture_filter", lambda: "tcp")
    with pytest.raises(RuntimeError, match="failed to start 3 times"):
        pipe.start_capture("eth-test")
    assert _DyingSniffer.starts == 3


def test_capture_keeps_one_session_until_stopped(pipe, monkeypatch):
    sessions = []

    class _LiveSniffer:
        def __init__(self, **kw):
            self.running = False
            sessions.append(self)

        def start(self):
            self.running = True
            pipe._stop.set()                           # operator stops after start

        def stop(self):
            self.running = False

    monkeypatch.setattr(ids_pipeline, "AsyncSniffer", _LiveSniffer)
    monkeypatch.setattr(pipe, "_ticker", lambda: None)
    monkeypatch.setattr(pipe, "_capture_heartbeat", lambda: None)
    monkeypatch.setattr(pipe, "_worker", lambda: None)
    monkeypatch.setattr(pipe, "_capture_filter", lambda: "tcp")
    pipe.start_capture("eth-test")
    assert len(sessions) == 1 and sessions[0].running is False


# - 2 Oct 2026 CICIDS pcap replay fixes

def test_rst_after_closed_flow_does_not_start_a_one_packet_flow(pipe):
    """The trailing RST+ACK after a FIN-closed (already scored) flow must not become a new flow."""
    feed(pipe, tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"), tcp("10.0.0.5", "8.8.4.4", 80, 4444, "SA"),
         tcp("8.8.4.4", "10.0.0.5", 4444, 80, "FA"))
    pipe._inference_batch()                              # flow closed on FIN, scored, dropped
    assert pipe.flow_tracker == {}
    feed(pipe, tcp("10.0.0.5", "8.8.4.4", 80, 4444, "RA"))
    assert pipe.flow_tracker == {} and pipe._orphan_rst_packets == 1


def test_rst_inside_an_open_flow_is_still_counted(pipe):
    feed(pipe, tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"), tcp("10.0.0.5", "8.8.4.4", 80, 4444, "RA"))
    flow = next(iter(pipe.flow_tracker.values()))
    assert flow["packets"] == 2 and flow["done"] is True


def test_active_stats_are_zero_without_an_idle_gap(pipe):
    """CICIDS2017 CSV: Active > 0 only ever occurs together with Idle > 0."""
    pkts = [tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"), tcp("8.8.4.4", "10.0.0.5", 4444, 80, "A"),
            tcp("8.8.4.4", "10.0.0.5", 4444, 80, "A")]
    for t, p in zip((0.0, 1.0, 2.0), pkts):              # 2 s of activity, no gap >= 5 s
        p.time = t
    feed(pipe, *pkts)
    key = next(iter(pipe.flow_tracker))
    f = dict(zip(FEATURE_ORDER, pipe._extract_flow_features(key)))
    assert f["Idle Mean"] == 0 and f["Active Mean"] == 0 and f["Active Max"] == 0


def test_alert_names_the_targeted_port(pipe):
    """dst_port lets an operator tell e.g. a :8080 flood from WSL/host control traffic."""
    pipe.autoencoder.delta = 0.9
    feed(pipe, tcp("8.8.4.4", "10.0.0.5", 4444, 8080, "S"), tcp("8.8.4.4", "10.0.0.5", 4444, 8080, "FA"))
    pipe._inference_batch()
    alert = pipe.redis_client.alerts()[0]
    assert (alert["dst_ip"], alert["dst_port"]) == ("10.0.0.5", 8080)


def test_udp_flows_do_not_count_toward_the_connection_rate(pipe):
    """CICIDS replay: workstations' DNS bursts (UDP) must not look like a connection flood."""
    for i in range(50):
        feed(pipe, IP(src="10.0.0.7", dst="10.0.0.53") / UDP(sport=40000 + i, dport=53))
    feed(pipe, tcp("10.0.0.7", "10.0.0.5", 5555, 80, "S"))
    assert pipe._source_rate("10.0.0.7", time.time()) == pytest.approx(1 / pipe.RATE_WINDOW_S, abs=0.01)


@pytest.mark.parametrize("env,expected", [
    ({}, (10.0, 30.0)),                                                    # measured defaults
    ({"IDS_RF_MIN_SRC_RATE": "20", "IDS_RATE_FLOOD_CONN_PER_S": "80"}, (20.0, 80.0)),
    ({"IDS_RF_MIN_SRC_RATE": "abc"}, (10.0, 30.0)),                        # invalid -> default
    ({"IDS_RF_MIN_SRC_RATE": "-5"}, (10.0, 30.0)),                         # non-positive -> default
    ({"IDS_RF_MIN_SRC_RATE": "50", "IDS_RATE_FLOOD_CONN_PER_S": "40"}, (10.0, 30.0)),  # flood < gate
])
def test_rate_thresholds_are_configurable_and_validated(env, expected):
    assert RealTimeIDSPipeline._load_rate_thresholds(env) == expected


def test_calibrate_rate_recommends_margins_over_the_normal_peak(tmp_path):
    import calibrate_rate
    rows = [{"ts": 1000 + i * 0.1, "src_ip": "10.0.0.2", "protocol": 6} for i in range(80)]  # 8/s
    rows += [{"ts": 1000 + i, "src_ip": "10.0.0.3", "protocol": 17} for i in range(500)]     # UDP ignored
    path = tmp_path / "normal.csv"
    __import__("pandas").DataFrame(rows).to_csv(path, index=False)
    peaks = calibrate_rate.peak_rates(__import__("pandas").read_csv(path), 10.0)
    assert peaks == {"10.0.0.2": 8.0}
