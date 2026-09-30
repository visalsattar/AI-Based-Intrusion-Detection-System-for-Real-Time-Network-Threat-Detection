#!/usr/bin/env python3
"""
Benchmark the deployed live IDS path.

Measures:
  1) packet_callback latency
  2) completed-flow batch / inference latency
  3) completed-flow -> alert latency (including evidence + Redis when enabled)
  4) Redis XADD latency
  5) sustained packet / flow throughput

This intentionally exercises:
  Scapy packet ingestion -> live flow extraction -> scaler -> Autoencoder ->
  Random Forest -> fusion/decision -> evidence snapshot -> Redis XADD.

The offline CNN is NOT loaded or benchmarked.

Run from the project root, where backend/src is importable and models live in
backend/models:

    python backend/benchmark_live_pipeline.py --flows 500 --warmup 50

For a Redis-backed end-to-end run, Redis must be running and REDIS_* settings
must be available exactly as in the deployed project. The benchmark refuses to
silently invent Redis performance if Redis is unavailable.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path
from types import MethodType

# Make backend/src importable when this script is run from the project root.
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    from scapy.all import IP, TCP, Raw
except Exception as exc:
    raise SystemExit(
        f"Scapy is required in the project environment: {exc}"
    )

from ids_pipeline import RealTimeIDSPipeline


def percentile(values, q):
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    frac = k - lo
    return xs[lo] + (xs[hi] - xs[lo]) * frac


def stats_ms(values_ns):
    vals = [v / 1e6 for v in values_ns if v is not None]
    if not vals:
        return {}
    return {
        "count": len(vals),
        "min_ms": min(vals),
        "p50_ms": percentile(vals, 0.50),
        "p95_ms": percentile(vals, 0.95),
        "p99_ms": percentile(vals, 0.99),
        "max_ms": max(vals),
        "mean_ms": statistics.fmean(vals),
    }


def make_flow_packets(index: int):
    """
    Four-packet TCP flow:
      SYN
      forward payload
      backward payload
      FIN/ACK

    Reserved TEST-NET-style benchmarking address space is used so the benchmark
    cannot target a real public source address. Auto-blocking is disabled.
    """
    # 198.18.0.0/15 is reserved for benchmarking/network-device testing.
    third = (index // 240) % 128
    fourth = (index % 240) + 1
    src = f"198.18.{third}.{fourth}"
    dst = "198.19.0.1"
    sport = 20000 + (index % 30000)
    dport = 443

    base = time.time()
    packets = [
        IP(src=src, dst=dst) /
        TCP(sport=sport, dport=dport, flags="S", seq=1000, window=64240),

        IP(src=src, dst=dst) /
        TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=1,
            window=64240) /
        Raw(b"A" * 100),

        IP(src=dst, dst=src) /
        TCP(sport=dport, dport=sport, flags="PA", seq=5000, ack=1101,
            window=32120) /
        Raw(b"B" * 80),

        IP(src=src, dst=dst) /
        TCP(sport=sport, dport=dport, flags="FA", seq=1101, ack=5081,
            window=64240),
    ]

    # Deterministic timestamps make IAT/active/idle features stable.
    for offset, packet in zip((0.0, 0.010, 0.020, 0.030), packets):
        packet.time = base + offset
    return packets, src


class RedisTimingProxy:
    """Transparent Redis wrapper that records XADD duration."""

    def __init__(self, client):
        self._client = client
        self.xadd_times_ns = []
        self.xadd_count = 0
        self.xadd_errors = 0

    def xadd(self, *args, **kwargs):
        start = time.perf_counter_ns()
        try:
            return self._client.xadd(*args, **kwargs)
        except Exception:
            self.xadd_errors += 1
            raise
        finally:
            self.xadd_times_ns.append(time.perf_counter_ns() - start)
            self.xadd_count += 1

    def __getattr__(self, name):
        return getattr(self._client, name)


def install_timing_hooks(pipeline, timings, final_packet_times):
    """
    Hook only measurement boundaries. The underlying pipeline methods still run
    unchanged.
    """
    original_batch = pipeline._inference_batch
    original_process = pipeline._process_prediction

    def timed_batch(self):
        start = time.perf_counter_ns()
        try:
            return original_batch()
        finally:
            timings["batch_ns"].append(time.perf_counter_ns() - start)

    def timed_process(self, flow_key, recon_error, rf_attack_prob=None,
                      threat_name=None):
        src = None
        try:
            src = self.flow_tracker[flow_key].get("init_src")
        except Exception:
            pass

        start = time.perf_counter_ns()
        try:
            return original_process(
                flow_key, recon_error, rf_attack_prob, threat_name
            )
        finally:
            end = time.perf_counter_ns()
            timings["process_ns"].append(end - start)

            # Only record an E2E value when this source had a final packet
            # timestamp in this benchmark iteration.
            if src in final_packet_times:
                timings["flow_to_process_ns"].append(
                    start - final_packet_times.pop(src)
                )

    pipeline._inference_batch = MethodType(timed_batch, pipeline)
    pipeline._process_prediction = MethodType(timed_process, pipeline)


def build_pipeline(args):
    model_dir = Path(args.model_dir)
    model_path = model_dir / "autoencoder.h5"
    scaler_path = model_dir / "feature_scaler.pkl"

    if not model_path.exists():
        raise SystemExit(f"Missing model: {model_path}")
    if not scaler_path.exists():
        raise SystemExit(f"Missing scaler: {scaler_path}")

    # Threshold=0 forces the alert gate open for benchmarking while preserving
    # the actual AE/RF/fusion computation. Auto-block remains explicitly OFF.
    pipeline = RealTimeIDSPipeline(
        model_path=str(model_path),
        feature_extractor_path=str(scaler_path),
        alert_threshold=0.0,
        packet_batch_size=args.packet_batch_size,
        flow_idle_timeout=120.0,
        max_packets_per_flow=2000,
        batch_interval=60.0,
        alert_cooldown=0.0,
        block_ttl=900.0,
        sweep_interval=60.0,
    )

    if pipeline.random_forest is None:
        raise SystemExit(
            "Random Forest did not load. This benchmark is specifically for "
            "the deployed RF + Autoencoder fusion path."
        )

    # Never enable destructive IPS behavior in a performance benchmark.
    pipeline._settings_cache = {
        "sensitivity": "medium",
        "criticalThreshold": 0.95,
        "highThreshold": 0.85,
        "autoBlock": False,
    }
    pipeline._settings_loaded_at = time.time()

    # Mark benchmark traffic so evidence generated by this run is identifiable.
    pipeline.evidence_origin = "live_pipeline_benchmark"

    return pipeline


def run(args):
    os.environ.setdefault("IDS_AE_ONLY_ALERTING_VALIDATED", "false")

    pipeline = build_pipeline(args)

    redis_proxy = None
    if pipeline.redis_client is not None:
        redis_proxy = RedisTimingProxy(pipeline.redis_client)
        pipeline.redis_client = redis_proxy
    elif args.require_redis:
        raise SystemExit(
            "Redis is unavailable. Re-run with Redis running, or omit "
            "--require-redis for a model/ingestion-only diagnostic."
        )

    timings = {
        "packet_ns": [],
        "batch_ns": [],
        "process_ns": [],
        "flow_to_process_ns": [],
    }

    final_packet_times = {}
    install_timing_hooks(pipeline, timings, final_packet_times)

    # Warmup prevents first TensorFlow prediction/model initialization from
    # contaminating the measured distribution.
    for i in range(args.warmup_flows):
        packets, _ = make_flow_packets(i)
        for packet in packets:
            pipeline.packet_callback(packet)
    # Ensure no warmup flow remains queued.
    pipeline._inference_batch()

    # Clear measurement arrays after warmup.
    for key in timings:
        timings[key].clear()
    if redis_proxy:
        redis_proxy.xadd_times_ns.clear()
        redis_proxy.xadd_count = 0
        redis_proxy.xadd_errors = 0

    # Benchmark.
    start_all = time.perf_counter_ns()
    packet_count = 0

    for i in range(args.warmup_flows, args.warmup_flows + args.flows):
        packets, src = make_flow_packets(i)

        for packet_index, packet in enumerate(packets):
            if packet_index == len(packets) - 1:
                # Record immediately BEFORE the final packet enters the live
                # callback. If this packet crosses the batch boundary, the
                # callback may synchronously run inference and alert emission.
                final_packet_times[src] = time.perf_counter_ns()

            packet_start = time.perf_counter_ns()
            pipeline.packet_callback(packet)
            timings["packet_ns"].append(
                time.perf_counter_ns() - packet_start
            )
            packet_count += 1

    # Flush anything left below the batch boundary.
    pipeline._inference_batch()

    elapsed_ns = time.perf_counter_ns() - start_all
    elapsed_s = elapsed_ns / 1e9

    # The process hook may run after final_packet_times was populated. Any
    # unmatched source means that the flow was not processed in the benchmark
    # window and is explicitly reported rather than silently ignored.
    unmatched = len(final_packet_times)

    result = {
        "benchmark": "Step 6 live RF + Autoencoder performance",
        "cnn_included": False,
        "flows": args.flows,
        "warmup_flows": args.warmup_flows,
        "packets_per_flow": 4,
        "packet_count": packet_count,
        "packet_batch_size": args.packet_batch_size,
        "elapsed_s": elapsed_s,
        "throughput": {
            "flows_per_second": args.flows / elapsed_s,
            "packets_per_second": packet_count / elapsed_s,
        },
        "latency_ms": {
            "packet_callback": stats_ms(timings["packet_ns"]),
            "inference_batch_and_postprocessing": stats_ms(timings["batch_ns"]),
            "process_prediction": stats_ms(timings["process_ns"]),
            "final_packet_to_prediction_processing": stats_ms(
                timings["flow_to_process_ns"]
            ),
        },
        "redis": None,
        "unmatched_final_packet_sources": unmatched,
        "warnings": [],
        "environment": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
        },
    }

    if redis_proxy:
        result["redis"] = {
            "available": True,
            "xadd_count": redis_proxy.xadd_count,
            "xadd_errors": redis_proxy.xadd_errors,
            "xadd_latency_ms": stats_ms(redis_proxy.xadd_times_ns),
        }
    else:
        result["redis"] = {
            "available": False,
            "xadd_count": 0,
            "xadd_errors": 0,
            "xadd_latency_ms": {},
        }
        result["warnings"].append(
            "Redis unavailable: this is not a complete end-to-end alert transport benchmark."
        )

    if unmatched:
        result["warnings"].append(
            f"{unmatched} completed flows were not observed by the prediction timing hook."
        )

    print(json.dumps(result, indent=2))

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nSaved: {output}")

    pipeline._stop.set()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--model-dir",
        default=str(ROOT / "models"),
        help="Directory containing autoencoder.h5 and feature_scaler.pkl",
    )
    parser.add_argument("--flows", type=int, default=500)
    parser.add_argument("--warmup-flows", type=int, default=50)
    parser.add_argument("--packet-batch-size", type=int, default=100)
    parser.add_argument(
        "--require-redis",
        action="store_true",
        help="Fail instead of running a non-Redis diagnostic if Redis is unavailable",
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "evidence" / "live_pipeline_benchmark.json"),
    )
    args = parser.parse_args()

    if args.flows < 10:
        parser.error("--flows should be at least 10")
    if args.warmup_flows < 0:
        parser.error("--warmup-flows cannot be negative")
    if args.packet_batch_size < 1:
        parser.error("--packet-batch-size must be positive")

    run(args)


if __name__ == "__main__":
    main()
