"""
Training/serving skew report for the live sensor.

The models were fitted on CICFlowMeter output; the sensor computes the same 78 columns itself
from Scapy packets. If those computations differ, every score is measured against the wrong
yardstick -- which looks exactly like "the RF calls everything Benign and the AE screams".
This report compares what the sensor really emits with what the scaler saw in training.

1. Capture normal traffic for a while (an hour of your own browsing is fine):
       IDS_DUMP_FEATURES=live_features.csv python main.py --mode ids --interface <name>
2. Then:
       python tools/skew_report.py live_features.csv

The dump contains IP addresses. Keep it private; drop the src_ip/dst_ip columns before sharing.
"""
import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd

AE_OVERRIDE_CONF = 0.97   # ids_pipeline default; alert fires on the AE alone above this score


def _pct(x):
    return f"{100 * x:5.1f}%"


def build_report(live: pd.DataFrame, scaler, threshold=None, top=15) -> dict:
    names = [str(n) for n in scaler.feature_names_in_]
    missing = [n for n in names if n not in live.columns]
    if missing:
        raise SystemExit(f"dump is missing {len(missing)} scaler columns, e.g. {missing[:3]}")

    X = live[names].to_numpy(dtype=float)
    lo, hi = np.asarray(scaler.data_min_, float), np.asarray(scaler.data_max_, float)
    below, above = (X < lo).mean(axis=0), (X > hi).mean(axis=0)
    span = np.where(hi - lo == 0, 1.0, hi - lo)
    scaled_median = np.median((X - lo) / span, axis=0)
    zero_share = (X == 0).mean(axis=0)

    feats = pd.DataFrame({
        "feature": names, "below_train_min": below, "above_train_max": above,
        "out_of_range": below + above, "median_scaled": scaled_median,
        "zero_share": zero_share, "train_max": hi,
    })
    out = {"n_flows": len(live), "features": feats}

    err = live["recon_error"].to_numpy(dtype=float)
    out["recon_pcts"] = {p: float(np.percentile(err, p)) for p in (50, 90, 99)}
    if threshold:
        out["threshold"] = threshold
        out["share_above_threshold"] = float((err > threshold).mean())
        out["share_ae_override"] = float((err > threshold * AE_OVERRIDE_CONF / (1 - AE_OVERRIDE_CONF)).mean())
    rf = pd.to_numeric(live.get("rf_prob"), errors="coerce").dropna()
    if len(rf):
        out["rf"] = {"n": len(rf), "median": float(rf.median()),
                     "gt_0.5": float((rf > 0.5).mean()), "gt_0.9": float((rf > 0.9).mean())}

    out["always_zero_live"] = feats[(feats.zero_share == 1.0) & (feats.train_max > 0)].feature.tolist()
    out["worst"] = feats.sort_values("out_of_range", ascending=False).head(top)
    return out


def print_report(r: dict, say=print):
    say(f"\nLive flows analysed: {r['n_flows']}")
    say("\nAUTOENCODER")
    p = r["recon_pcts"]
    say(f"  reconstruction error  p50={p[50]:.5f}  p90={p[90]:.5f}  p99={p[99]:.5f}")
    if "threshold" in r:
        t = r["threshold"]
        say(f"  calibrated threshold  {t:.6f}  ->  {_pct(r['share_above_threshold'])} of live flows exceed it")
        say(f"  AE-override level     {t * AE_OVERRIDE_CONF / (1 - AE_OVERRIDE_CONF):.4f}  ->  "
            f"{_pct(r['share_ae_override'])} of live flows would alert on the AE alone")
    if "rf" in r:
        f = r["rf"]
        say(f"\nRANDOM FOREST  P(attack) over {f['n']} flows: median={f['median']:.3f}  "
            f">0.5: {_pct(f['gt_0.5'])}  >0.9: {_pct(f['gt_0.9'])}")
    say("\nFEATURES MOST OFTEN OUTSIDE THE RANGE THE SCALER SAW IN TRAINING")
    say(f"  {'feature':32} {'>max':>7} {'<min':>7} {'median (0..1 scaled)':>21} {'zero':>7}")
    for _, x in r["worst"].iterrows():
        if x.out_of_range == 0:
            break
        say(f"  {x.feature:32} {_pct(x.above_train_max):>7} {_pct(x.below_train_min):>7} "
            f"{x.median_scaled:>21.3f} {_pct(x.zero_share):>7}")
    if r["always_zero_live"]:
        say("\nALWAYS 0 LIVE but non-zero in training (not measured by the sensor): "
            + ", ".join(r["always_zero_live"]))
    say("\nHow to read it: a feature that is far out of range on most benign flows is measured differently "
        "from CICFlowMeter (units, definition, header vs payload bytes...). Fix those before trusting any score.")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv")
    ap.add_argument("--scaler", default="models/feature_scaler.pkl")
    ap.add_argument("--metrics", default="models/real_metrics.json")
    ap.add_argument("--threshold", type=float, help="override the reconstruction threshold")
    ap.add_argument("--top", type=int, default=15)
    a = ap.parse_args(argv)

    thr = a.threshold
    if thr is None and os.path.exists(a.metrics):
        thr = json.load(open(a.metrics)).get("autoencoder", {}).get("threshold")
    print_report(build_report(pd.read_csv(a.csv), joblib.load(a.scaler), thr, a.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
