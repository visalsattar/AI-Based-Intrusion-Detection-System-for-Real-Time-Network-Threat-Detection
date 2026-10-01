"""
Replay a pcap through the REAL live pipeline (Scapy feature extractor -> scaler -> AE + RF ->
live alert rule) and score every flow against known attacker/victim IPs.

Why: the shipped models were evaluated on CIC's CSV, whose features were computed by
CICFlowMeter (Java). This tests the whole live path, including our own extractor, on CIC's raw
packets: e.g. Friday-WorkingHours.pcap, DDoS (LOIC) 172.16.0.1 -> 192.168.10.50, ~15:56-16:16
local time (ADT, UTC-3) per the CIC CICIDS2017 description.

Replay runs faster than real time, so the pipeline's clock (datetime.now / time.time inside
ids_pipeline) is driven by packet timestamps: idle timeouts and flow durations behave as live.
Nothing is sent to Redis; no evidence files are written; AutoBlock is off.

Usage (from backend/):
  python replay_pcap.py Friday-WorkingHours.pcap --from 15:50 --to 16:25
  python replay_pcap.py Friday-WorkingHours.pcap --from 15:50 --to 16:25 --rf-dir live_flow_v2
Output: evidence/replay_<pcap name>.csv (one row per scored flow) + printed metrics.
"""
import argparse
import datetime as _dt
import logging
import os
import sys
import time as _time

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))


class _PacketClock:
    """Stands in for ids_pipeline's `datetime` and `time` so flow timing follows the pcap."""
    now_ts = 0.0

    class datetime(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return _dt.datetime.fromtimestamp(_PacketClock.now_ts)

    class time:
        @staticmethod
        def time():
            return _PacketClock.now_ts

        monotonic = staticmethod(_time.monotonic)
        sleep = staticmethod(_time.sleep)
        perf_counter = staticmethod(_time.perf_counter)


def _records(path):
    """Yield (timestamp, raw bytes) without dissecting, so skipping out-of-window packets is cheap."""
    # RawPcapReader opens either format (CIC's Friday-WorkingHours.pcap is really pcapng);
    # the per-packet metadata differs, so read the timestamp from whichever fields exist.
    from scapy.utils import RawPcapReader
    for data, meta in RawPcapReader(path):
        if hasattr(meta, "sec"):
            yield meta.sec + meta.usec / 1e6, data
        else:
            yield ((meta.tshigh << 32) | meta.tslow) / float(meta.tsresol), data


def _window(day_ts, hhmm, tz_hours):
    h, m = map(int, hhmm.split(":"))
    day = _dt.datetime.fromtimestamp(day_ts, _dt.timezone(_dt.timedelta(hours=tz_hours))).date()
    local = _dt.datetime(day.year, day.month, day.day, h, m,
                         tzinfo=_dt.timezone(_dt.timedelta(hours=tz_hours)))
    return local.timestamp()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--from", dest="t_from", help="window start HH:MM in --tz local time")
    ap.add_argument("--to", dest="t_to", help="window end HH:MM in --tz local time")
    ap.add_argument("--tz", type=float, default=-3, help="UTC offset of --from/--to (CIC: -3)")
    ap.add_argument("--attacker", nargs="+", default=["172.16.0.1"])
    ap.add_argument("--victim", nargs="+", default=["192.168.10.50"])
    ap.add_argument("--rf-dir", default="", help="RF directory under models/ (default: shipped RF)")
    ap.add_argument("--limit", type=int, default=0, help="stop after N in-window packets")
    ap.add_argument("--out", default="")
    args = ap.parse_args(argv)

    os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
    if args.rf_dir:
        os.environ["IDS_RF_DIR"] = args.rf_dir
    else:
        os.environ.pop("IDS_RF_DIR", None)
    logging.basicConfig(level=logging.WARNING)
    from scapy.all import Ether
    import ids_pipeline
    from ids_pipeline import RealTimeIDSPipeline

    out = args.out or os.path.join(
        "evidence", f"replay_{os.path.splitext(os.path.basename(args.pcap))[0]}"
                    f"{'_' + args.rf_dir if args.rf_dir else ''}.csv")
    if os.path.exists(out):
        os.remove(out)

    p = RealTimeIDSPipeline(model_path="models/autoencoder.h5",
                            feature_extractor_path="models/feature_scaler.pkl",
                            alert_threshold=0.85, packet_batch_size=5000)
    p.redis_client = None
    p._queue = None                                   # synchronous: no worker thread
    p._load_settings = lambda: {"autoBlock": False}
    p._dump_path, p._dump_rows, p._dump_max = out, 0, 10**9
    ids_pipeline.save_threat_evidence = lambda alert: {}
    ids_pipeline.datetime = _PacketClock.datetime
    ids_pipeline.time = _PacketClock.time

    lo = hi = None
    seen = used = 0
    t0 = _time.perf_counter()
    for ts, data in _records(args.pcap):
        seen += 1
        if lo is None and args.t_from:
            lo = _window(ts, args.t_from, args.tz)
            hi = _window(ts, args.t_to, args.tz) if args.t_to else float("inf")
        if lo is not None and not (lo <= ts <= hi):
            if hi is not None and ts > hi + 300:
                break                                  # pcap is time-ordered; done
            continue
        _PacketClock.now_ts = ts
        pkt = Ether(data)
        pkt.time = ts
        p.packet_callback(pkt)
        used += 1
        if used % 200000 == 0:
            print(f"  {used:,} packets replayed ({used / (_time.perf_counter() - t0):,.0f}/s), "
                  f"{p._dump_rows:,} flows scored", flush=True)
        if args.limit and used >= args.limit:
            break
    _PacketClock.now_ts += 10_000                      # every open flow is now idle
    p.flush()
    print(f"Read {seen:,} packets, replayed {used:,} in window, scored {p._dump_rows:,} flows "
          f"in {_time.perf_counter() - t0:,.0f}s -> {out}")
    if not os.path.exists(out):
        raise SystemExit("No flows scored (empty window?).")
    report(out, args.attacker, args.victim, p.recon_threshold)


def report(csv_path, attackers, victims, recon_threshold):
    d = pd.read_csv(csv_path)
    pair = ((d.src_ip.isin(attackers) & d.dst_ip.isin(victims)) |
            (d.src_ip.isin(victims) & d.dst_ip.isin(attackers)))
    y = pair.astype(int).values
    ae = d.recon_error / (d.recon_error + recon_threshold)
    rf = pd.to_numeric(d.rf_prob, errors="coerce").fillna(0.0)
    fused = 0.5 * ae + 0.5 * rf
    s = np.where(rf > 0.9, np.maximum(fused, rf), fused)
    s = np.where(ae > 0.97, np.maximum(s, ae), s)
    print(f"\nFlows: {len(d):,}  attack (attacker<->victim): {y.sum():,}  other: {(y == 0).sum():,}")
    for name, pred in [("RF > 0.5", rf > 0.5), ("RF > 0.9 (override)", rf > 0.9),
                       ("LIVE rule > 0.85", s > 0.85)]:
        pred = np.asarray(pred)
        tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
        rec = tp / max(1, y.sum()); fpr = fp / max(1, (y == 0).sum())
        prec = tp / max(1, tp + fp)
        print(f"  {name:22} recall {rec:7.2%}   precision {prec:7.2%}   false-alert rate on other flows {fpr:7.3%}")
    print("NOTE: 'other' flows are all non attacker<->victim traffic in the window, assumed benign "
          "per CIC labels for that period; verify against CIC's CSV labels if available.")


if __name__ == "__main__":
    main()
