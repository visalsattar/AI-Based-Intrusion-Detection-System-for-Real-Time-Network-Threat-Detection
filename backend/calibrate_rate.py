"""
Calibrate the connection-rate thresholds (IDS_RF_MIN_SRC_RATE, IDS_RATE_FLOOD_CONN_PER_S) for
YOUR network from captures of NORMAL traffic (start-capture.ps1 -FeatureDump ...).

The defaults (RF gate 10/s, flood alert 30/s) were measured on one laptop: normal peak 4.3 new
TCP connections/s per source vs floods of 87-247/s. A busy server, proxy or NAT gateway can be
legitimately much busier, so measure before deploying elsewhere.

Rule of thumb used here: gate = max(default, 2 x normal peak), flood = max(default, 5 x normal
peak). Rates are computed per source over a sliding RATE_WINDOW_S window, TCP only (as live).
The dump timestamp is the scoring time at 1 s resolution, so rates are approximate.

Usage (from backend/):
  python calibrate_rate.py evidence/benign_long.csv [more_normal.csv ...] [--exclude-ip 1.2.3.4]
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))


def peak_rates(frame, window_s):
    """Peak new-TCP-flow rate (per second) per source over a sliding window."""
    tcp = frame[frame.protocol == 6]
    out = {}
    for src, g in tcp.groupby("src_ip"):
        t = np.sort(g.ts.to_numpy(dtype=float))
        counts = np.searchsorted(t, t, side="right") - np.searchsorted(t, t - window_s, side="left")
        out[src] = counts.max() / window_s
    return out


def main(argv=None):
    from ids_pipeline import RealTimeIDSPipeline as P
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captures", nargs="+", help="feature dumps of NORMAL traffic only")
    ap.add_argument("--exclude-ip", action="append", default=[], help="known attacker/test IPs to ignore")
    args = ap.parse_args(argv)

    frames = [pd.read_csv(f, usecols=["ts", "src_ip", "protocol"]) for f in args.captures]
    data = pd.concat(frames)
    data = data[~data.src_ip.isin(args.exclude_ip)]
    span_h = (data.ts.max() - data.ts.min()) / 3600 if len(data) else 0
    peaks = peak_rates(data, P.RATE_WINDOW_S)
    if not peaks:
        raise SystemExit("No TCP flows in the captures.")

    top = sorted(peaks.items(), key=lambda kv: -kv[1])
    print(f"{len(data):,} flows from {len(peaks)} TCP sources over ~{span_h:.1f} h "
          f"(window {P.RATE_WINDOW_S:.0f} s)")
    print("Busiest sources (peak new TCP connections/s):")
    for src, r in top[:8]:
        print(f"  {src:40} {r:6.1f}/s")
    peak = top[0][1]
    gate = max(P.RF_MIN_SRC_RATE, round(2 * peak, 1))
    flood = max(P.RATE_FLOOD_CONN_PER_S, round(5 * peak, 1), gate)
    print(f"\nNormal peak: {peak:.1f}/s")
    print("Recommended (put in backend/.env, then restart capture):")
    print(f"  IDS_RF_MIN_SRC_RATE={gate:g}")
    print(f"  IDS_RATE_FLOOD_CONN_PER_S={flood:g}")
    if span_h < 1:
        print("WARNING: less than 1 hour of traffic; capture longer (ideally a busy working day).")


if __name__ == "__main__":
    main()
