"""
Train a Random Forest on LIVE captured flows (IDS_DUMP_FEATURES csv files) -> models/live_flow_v1/.

Why: the shipped RF only knows the CICIDS2017 Friday LOIC flood profile, so it does not fire
on other floods seen live. This trains on what the sensor actually emits, with labels you
assign from the lab setup (attacker IP / target port).

Drop-in compatible with the live pipeline: features go through the SAME preprocessing as
ids_pipeline._score_flows (TRAINING_ZERO_FEATURES zeroed, TRAINING_BINARY_FEATURES clamped,
then the shipped feature_scaler.pkl), so the saved RF expects exactly what the pipeline feeds it.

Shortcut guard: features that identify the lab SETUP rather than attack BEHAVIOUR (destination
port, TCP initial windows = the attacker's OS) are zeroed before training, so the trees cannot
split on them. Check the printed feature importances for any other shortcut.

The split here is chronological inside the same captures, so the held-out score is a
smoke test only. Real evaluation = evaluate a NEW capture with --evaluate.

Usage (from backend/):
  python train_live_flow.py --attack evidence/lab_run2.csv --attacker-ip 192.168.18.25 \
      --target-port 8080 --benign evidence/benign_long.csv [--out models/live_flow_v1]
  python train_live_flow.py --evaluate evidence/new_run.csv --attacker-ip 192.168.18.25 \
      --target-port 8080 [--out models/live_flow_v1]
"""
import argparse
import json
import os
import sys
import time

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

SHORTCUT_FEATURES = ("Destination Port", "Init_Win_bytes_forward", "Init_Win_bytes_backward")


def preprocess(frame, scaler):
    from ids_pipeline import RealTimeIDSPipeline as P
    names = [str(n) for n in scaler.feature_names_in_]
    X = frame[names].astype(float).copy()
    for c in P.TRAINING_ZERO_FEATURES:
        X[c] = 0.0
    for c in P.TRAINING_BINARY_FEATURES:
        X[c] = (X[c] > 0).astype(float)
    for c in SHORTCUT_FEATURES:
        X[c] = 0.0
    return pd.DataFrame(scaler.transform(X), columns=names)


def label(frame, attacker_ip, target_port):
    """1 = attacker -> target port; 0 = flows not involving the attacker; None = ambiguous (dropped)."""
    ips = [attacker_ip] if isinstance(attacker_ip, str) else list(attacker_ip)
    attack = frame.src_ip.isin(ips) & (frame.dst_port == target_port)
    involves = frame.src_ip.isin(ips) | frame.dst_ip.isin(ips)
    y = pd.Series(np.where(attack, 1, 0), index=frame.index)
    return y[attack | ~involves]


def chrono_split(frame, frac=0.7):
    cut = frame.ts.quantile(frac)
    return frame[frame.ts <= cut], frame[frame.ts > cut]


def report(name, y, p):
    from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    out = {"rows": int(len(y)), "attack": int(y.sum()), "benign": int((y == 0).sum()),
           "precision": float(precision_score(y, p, zero_division=0)),
           "recall": float(recall_score(y, p, zero_division=0)),
           "f1": float(f1_score(y, p, zero_division=0)),
           "benign_false_alert_rate": float(fp / max(1, tn + fp)),
           "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}
    print(f"{name}: rows={out['rows']} attack={out['attack']} benign={out['benign']} "
          f"P={out['precision']:.4f} R={out['recall']:.4f} F1={out['f1']:.4f} "
          f"benign FP rate={out['benign_false_alert_rate']:.4%} (tn={tn} fp={fp} fn={fn} tp={tp})")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--attack", nargs="*", default=[], help="captures containing labelled attack flows")
    ap.add_argument("--benign", nargs="*", default=[], help="captures of benign-only traffic")
    ap.add_argument("--evaluate", nargs="*", default=[], help="NEW capture(s) to score with a trained model")
    ap.add_argument("--attacker-ip", required=True, nargs="+",
                    help="one or more attacker IPs (e.g. a LAN device and a WSL VM)")
    ap.add_argument("--target-port", type=int, required=True)
    ap.add_argument("--scaler", default="models/feature_scaler.pkl")
    ap.add_argument("--out", default="models/live_flow_v1")
    ap.add_argument("--attack-name", default="TCP Connect Flood (lab-trained)",
                    help="threat name shown on live alerts (written to label_map.json)")
    args = ap.parse_args(argv)
    scaler = joblib.load(args.scaler)

    if args.evaluate:
        rf = joblib.load(os.path.join(args.out, "random_forest.pkl"))
        for f in args.evaluate:
            d = pd.read_csv(f)
            y = label(d, args.attacker_ip, args.target_port)
            p = (rf.predict_proba(preprocess(d.loc[y.index], scaler))[:, 1] > 0.5).astype(int)
            report(f"EVALUATE {f}", y.values, p)
        return

    from sklearn.ensemble import RandomForestClassifier
    parts = []
    for f in args.attack:
        d = pd.read_csv(f)
        parts.append(d.loc[label(d, args.attacker_ip, args.target_port).index].assign(
            y=label(d, args.attacker_ip, args.target_port), source=f))
    for f in args.benign:
        d = pd.read_csv(f)
        if (d.src_ip.isin(args.attacker_ip) | d.dst_ip.isin(args.attacker_ip)).any():
            raise SystemExit(f"{f} contains attacker traffic; it is not benign-only")
        parts.append(d.assign(y=0, source=f))
    if not parts:
        raise SystemExit("give --attack and/or --benign captures")

    # Chronological split per capture, so no capture leaks its later flows into training.
    train, test = zip(*(chrono_split(p) for p in parts))
    train, test = pd.concat(train), pd.concat(test)
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", min_samples_leaf=2,
                                random_state=42, n_jobs=-1)
    rf.fit(preprocess(train, scaler), train.y)
    pred = rf.predict(preprocess(test, scaler))
    held = report("HELD-OUT (later 30% of each capture; same sessions = smoke test only)", test.y.values, pred)

    names = [str(n) for n in scaler.feature_names_in_]
    top = sorted(zip(rf.feature_importances_, names), reverse=True)[:12]
    print("Top features (check none is a setup artefact):")
    for imp, n in top:
        print(f"  {imp:.4f}  {n}")

    os.makedirs(args.out, exist_ok=True)
    joblib.dump(rf, os.path.join(args.out, "random_forest.pkl"))
    with open(os.path.join(args.out, "label_map.json"), "w", encoding="utf-8") as fh:
        json.dump({"0": "Benign", "1": args.attack_name}, fh, indent=2)
    meta = {"created": time.strftime("%Y-%m-%d %H:%M:%S"), "attack_captures": args.attack,
            "benign_captures": args.benign, "attacker_ip": args.attacker_ip,
            "target_port": args.target_port, "train_rows": int(len(train)),
            "train_attack": int(train.y.sum()), "shortcut_features_zeroed": list(SHORTCUT_FEATURES),
            "preprocessing": "TRAINING_ZERO/BINARY_FEATURES + models/feature_scaler.pkl (same as live)",
            "held_out_smoke_test": held,
            "top_features": [[n, float(i)] for i, n in top],
            "WARNING": "Held-out rows come from the same sessions as training. Not a generalisation "
                       "result; evaluate on a NEW capture with --evaluate."}
    with open(os.path.join(args.out, "live_metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print(f"Saved {args.out}/random_forest.pkl and live_metrics.json (shipped models/ untouched).")


if __name__ == "__main__":
    main()
