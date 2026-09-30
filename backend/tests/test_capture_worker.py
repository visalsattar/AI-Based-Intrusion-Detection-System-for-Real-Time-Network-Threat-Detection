"""Round 3: PacketSummary storage, capture->worker queue, AutoBlock reconciliation."""
import queue
import subprocess
import threading
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

from scapy.all import IP, TCP, UDP, Ether, Raw

import ids_pipeline
from ids_pipeline import PacketSummary, summarize
from stubs import make_pipeline


def _tcp(src, dst, sport, dport, flags, payload=b"", t=0.0, seq=0, ack=0):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags,
                                             seq=seq, ack=ack, window=4096) / Raw(payload)
    p = Ether(bytes(p))          # dissect as a real capture would
    p.time = 1_700_000_000.0 + t
    return p


# ---------------------------------------------------------------- #2 summaries

def test_flow_stores_summaries_not_scapy_packets():
    p = make_pipeline()
    p.packet_callback(_tcp("8.8.8.8", "10.0.0.5", 5555, 80, "S"))
    (flow,) = p.flow_tracker.values()
    (entry,) = flow["packet_list"]
    assert isinstance(entry, PacketSummary)
    assert p.packet_buffer and all(isinstance(k, tuple) and len(k) == 3 for k in p.packet_buffer)


def test_summary_payload_excludes_ethernet_ip_tcp_headers():
    s = summarize(_tcp("8.8.8.8", "10.0.0.5", 5555, 80, "PA", b"x" * 10))
    ts, plen, hlen, flags, is_tcp = s[5]
    assert plen == 10 and hlen == 20 and is_tcp and flags == 0x18


def test_summary_rejects_non_transport():
    assert summarize(Ether() / IP(src="1.1.1.1", dst="2.2.2.2")) is None


def test_udp_summary_has_no_window_and_zero_flags():
    pkt = Ether(bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=5353) / Raw(b"abcd")))
    s = summarize(pkt)
    assert s[2] is None and s[5][3] == 0 and s[5][1] == 4 and s[5][2] == 8


def test_legacy_tuple_and_summary_produce_identical_features():
    pkts = [_tcp("10.0.0.1", "10.0.0.2", 1234, 80, "PA", b"a" * n, t=i * 0.1)
            for i, n in enumerate([5, 7, 9, 11, 13])]
    a, b = make_pipeline(), make_pipeline()
    for pk in pkts:
        a._ingest(pk)
    key = next(iter(a.flow_tracker))
    b.flow_tracker[key] = dict(a.flow_tracker[key])
    b.flow_tracker[key]["packet_list"] = [(pk, True) for pk in pkts]   # legacy form
    assert (a._extract_flow_features(key) == b._extract_flow_features(key)).all()


def test_handshake_still_verified_through_summary_path():
    p = make_pipeline()
    p._ingest(_tcp("8.8.8.8", "10.0.0.5", 5555, 80, "S", seq=100))
    p._ingest(_tcp("10.0.0.5", "8.8.8.8", 80, 5555, "SA", seq=900, ack=101))
    p._ingest(_tcp("8.8.8.8", "10.0.0.5", 5555, 80, "A", seq=101, ack=901))
    (flow,) = p.flow_tracker.values()
    assert flow["init_syn"] and flow["handshake_complete"]


def test_wrong_ack_does_not_complete_handshake():
    p = make_pipeline()
    p._ingest(_tcp("8.8.8.8", "10.0.0.5", 5555, 80, "S", seq=100))
    p._ingest(_tcp("10.0.0.5", "8.8.8.8", 80, 5555, "SA", seq=900, ack=101))
    p._ingest(_tcp("8.8.8.8", "10.0.0.5", 5555, 80, "A", seq=101, ack=12345))
    (flow,) = p.flow_tracker.values()
    assert not flow["handshake_complete"]


# ---------------------------------------------------------------- #3 queue / worker

def test_callback_only_enqueues_when_worker_mode():
    p = make_pipeline()
    p._queue = queue.Queue(maxsize=10)
    p.packet_callback(_tcp("8.8.8.8", "10.0.0.5", 5555, 80, "S"))
    assert p._queue.qsize() == 1
    assert p.flow_tracker == {}              # capture thread touched no flow state


def test_full_queue_drops_and_counts():
    p = make_pipeline()
    p._queue = queue.Queue(maxsize=1)
    for i in range(3):
        p.packet_callback(_tcp("8.8.8.8", "10.0.0.5", 5000 + i, 80, "S"))
    assert p._queue.qsize() == 1 and p._dropped_packets == 2


def test_health_report_includes_and_resets_drop_counter(caplog):
    p = make_pipeline()
    p._queue = queue.Queue(maxsize=1)
    p._dropped_packets = 7
    p._capture_health_at = time.monotonic() - 11
    with caplog.at_level("INFO", logger="ids_pipeline"):
        p._report_health()
    assert "dropped=7" in caplog.text and p._dropped_packets == 0


def test_worker_ingests_and_time_flushes_idle_flow():
    p = make_pipeline()
    p._queue = queue.Queue(maxsize=100)
    p.batch_interval = 0.05
    p.flow_idle_timeout = 0.0
    p._worker_thread = threading.Thread(target=p._worker, daemon=True)
    p._worker_thread.start()
    try:
        p.packet_callback(_tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"))
        deadline = time.time() + 3
        while p.autoencoder.rows_seen == 0 and time.time() < deadline:
            time.sleep(0.02)
    finally:
        p._stop.set()
        p._worker_thread.join(timeout=2)
    assert p.autoencoder.rows_seen == 1
    assert not p._worker_thread.is_alive()


def test_ticker_does_not_score_when_worker_owns_flushing():
    p = make_pipeline()
    p._worker_thread = SimpleNamespace()       # pretend a worker is running
    p._ingest(_tcp("8.8.4.4", "10.0.0.5", 4444, 80, "S"))
    for f in p.flow_tracker.values():
        f["last_seen"] = datetime.now() - timedelta(seconds=p.flow_idle_timeout + 1)
    p.batch_interval = 0.0
    p._tick_once()
    assert p.autoencoder.rows_seen == 0


# ---------------------------------------------------------------- iptables /32 reconciliation

def test_reconcile_strips_prefix_length_and_keeps_tracked_block(monkeypatch):
    p = make_pipeline()
    ip = "203.0.113.7"
    p._blocked = {}
    import json
    with open(p._autoblock_state_path, "w") as f:
        json.dump({ip: time.time() + 600}, f)

    calls = []

    def fake_fw(cmd):
        calls.append(cmd)
        out = f"-P INPUT ACCEPT\n-A INPUT -s {ip}/32 -m comment --comment IDS-AUTOBLOCK -j DROP\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out.encode(), stderr=b"")

    monkeypatch.setattr(ids_pipeline, "_fw", fake_fw)
    monkeypatch.setattr(ids_pipeline.platform, "system", lambda: "Linux")
    p._load_autoblock_state()

    assert ip in p._blocked                                  # state survived
    assert not any("-D" in c for c in calls)                 # tracked rule not deleted


def test_reconcile_removes_orphaned_ids_rule(monkeypatch):
    p = make_pipeline()
    ip = "198.51.100.9"
    deleted = []

    def fake_fw(cmd):
        if "-D" in cmd:
            deleted.append(cmd[cmd.index("-s") + 1])
        out = f"-A INPUT -s {ip}/32 -m comment --comment IDS-AUTOBLOCK -j DROP\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out.encode(), stderr=b"")

    monkeypatch.setattr(ids_pipeline, "_fw", fake_fw)
    monkeypatch.setattr(ids_pipeline.platform, "system", lambda: "Linux")
    p._load_autoblock_state()                                # no state file -> orphan
    assert deleted == [ip]                                   # bare IP, not "ip/32"