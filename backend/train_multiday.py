"""
Multi-day, multi-class Random Forest on all eight CICIDS2017 MachineLearningCVE days
-> models/multiday_v1/ (random_forest.pkl, label_map.json, multiday_metrics.json).

The shipped model (models/random_forest.pkl, Friday-afternoon DDoS only) is NOT changed.
Load this one live with IDS_RF_DIR=multiday_v1; the pipeline already supports multi-class RFs
(attack probability = 1 - P(BENIGN), threat name from label_map.json).

Preprocessing = the live pipeline's (TRAINING_ZERO/BINARY_FEATURES + shipped feature_scaler)
plus the shortcut zeroing of train_live_flow.py (Destination Port, Init_Win_bytes_*), so the
model cannot learn CIC's ports or attacker OS fingerprints.

Evaluations:
  A. per-day chronological split: first 80% of each day trains, last 20% tests (attacks seen).
  B. leave-one-day-out (binary attack vs benign): train on the other days, test on one day.
     Shows what happens on attack families never seen in training.

Usage (from backend/):  python train_multiday.py data/CICIDS2017/MachineLearningCSV.zip
"""
import argparse
import json
import os
import sys
import time
import zipfile

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

CLASSES = ["BENIGN", "DoS", "DDoS", "PortScan", "Brute Force", "Web Attack", "Bot",
           "Infiltration", "Heartbleed"]


def group(label):
    l = str(label).strip()
    if l == "BENIGN": return "BENIGN"
    if l == "DDoS": return "DDoS"
    if l.startswith("DoS"): return "DoS"
    if l == "PortScan": return "PortScan"
    if "Patator" in l: return "Brute Force"
    if l.startswith("Web Attack"): return "Web Attack"
    if l == "Bot": return "Bot"
    if l == "Infiltration": return "Infiltration"
    if l == "Heartbleed": return "Heartbleed"
    raise ValueError(f"unknown label {l!r}")


def load_days(zip_path, names):
    days = {}
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            if not info.filename.endswith(".csv"):
                continue
            day = os.path.basename(info.filename).replace(".pcap_ISCX.csv", "")
            d = pd.read_csv(z.open(info), encoding="latin-1", low_memory=False)
            d.columns = [c.strip() for c in d.columns]
            missing = [n for n in names if n not in d.columns]
            assert not missing, (day, missing[:3])
            X = d[names].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
            ok = X.notna().all(axis=1)
            y = d["Label"].map(group)
            days[day] = (X[ok].reset_index(drop=True), y[ok].reset_index(drop=True), int((~ok).sum()))
            print(f"  {day:48} rows {ok.sum():>9,}  dropped NaN/inf {int((~ok).sum()):>5}  "
                  f"attacks {int((y[ok] != 'BENIGN').sum()):>7,}", flush=True)
    return days


def preprocess(X, scaler):
    from ids_pipeline import RealTimeIDSPipeline as P
    from train_live_flow import SHORTCUT_FEATURES
    X = X.copy()
    for c in P.TRAINING_ZERO_FEATURES: X[c] = 0.0
    for c in P.TRAINING_BINARY_FEATURES: X[c] = (X[c] > 0).astype(float)
    for c in SHORTCUT_FEATURES: X[c] = 0.0
    return pd.DataFrame(scaler.transform(X), columns=X.columns)


def sample_train(X, y, benign_cap, per_class_cap, seed=42):
    rng = np.random.default_rng(seed)
    keep = []
    for cls in y.unique():
        idx = np.flatnonzero((y == cls).to_numpy())
        cap = benign_cap if cls == "BENIGN" else per_class_cap
        keep.append(rng.choice(idx, cap, replace=False) if len(idx) > cap else idx)
    keep = np.sort(np.concatenate(keep))
    return X.iloc[keep], y.iloc[keep]


CLASS_WEIGHT = None   # run 1 used "balanced_subsample": rare classes (Bot, Brute Force) swallowed benign flows


def rf(n_trees=100):
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=n_trees, min_samples_leaf=2, class_weight=CLASS_WEIGHT,
                                  n_jobs=-1, random_state=42)


def main(argv=None):
    from sklearn.metrics import classification_report, confusion_matrix
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zip")
    ap.add_argument("--out", default="models/multiday_v1")
    ap.add_argument("--benign-cap", type=int, default=1_200_000)
    ap.add_argument("--class-cap", type=int, default=150_000)
    ap.add_argument("--skip-lodo", action="store_true")
    args = ap.parse_args(argv)
    t0 = time.time()
    scaler = joblib.load("models/feature_scaler.pkl")
    names = [str(n) for n in scaler.feature_names_in_]
    print("Loading days:", flush=True)
    days = load_days(args.zip, names)
    metrics = {"created": time.strftime("%Y-%m-%d %H:%M:%S"), "classes": CLASSES,
               "dropped_nan_inf": {d: v[2] for d, v in days.items()}}

    # ---- A: per-day chronological 80/20 -------------------------------------------------------
    tr_X, tr_y, te_X, te_y = [], [], [], []
    for d, (X, y, _) in days.items():
        cut = int(len(X) * 0.8)
        tr_X.append(X.iloc[:cut]); tr_y.append(y.iloc[:cut]); te_X.append(X.iloc[cut:]); te_y.append(y.iloc[cut:])
    Xtr, ytr = sample_train(pd.concat(tr_X), pd.concat(tr_y), args.benign_cap, args.class_cap)
    Xte, yte = pd.concat(te_X), pd.concat(te_y)
    print(f"\nA. train {len(Xtr):,} rows (sampled) | test {len(Xte):,} rows (all, last 20% of each day)", flush=True)
    model = rf(100).fit(preprocess(Xtr, scaler), ytr.map(CLASSES.index))
    pred = model.predict(preprocess(Xte, scaler))
    yt = yte.map(CLASSES.index).to_numpy()
    present = sorted(set(yt) | set(pred))
    rep = classification_report(yt, pred, labels=present, target_names=[CLASSES[i] for i in present],
                                output_dict=True, zero_division=0)
    print(classification_report(yt, pred, labels=present, target_names=[CLASSES[i] for i in present],
                                digits=4, zero_division=0))
    att_true, att_pred = yt != 0, pred != 0
    bin_ = {"attack_recall": float((att_pred & att_true).sum() / max(1, att_true.sum())),
            "benign_false_alarm_rate": float((att_pred & ~att_true).sum() / max(1, (~att_true).sum())),
            "attack_precision": float((att_pred & att_true).sum() / max(1, att_pred.sum()))}
    print("A. binary view (any attack vs benign):", {k: round(v, 5) for k, v in bin_.items()}, flush=True)
    metrics["A_per_day_chronological"] = {"train_rows": int(len(Xtr)), "test_rows": int(len(Xte)),
                                          "per_class": rep, "binary": bin_,
                                          "confusion_matrix_labels": [CLASSES[i] for i in present],
                                          "confusion_matrix": confusion_matrix(yt, pred, labels=present).tolist()}

    # ---- B: leave-one-day-out, binary -------------------------------------------------------
    if not args.skip_lodo:
        print("\nB. leave-one-day-out (binary; attacks of the held-out day never seen):", flush=True)
        lodo = {}
        for held in days:
            if (days[held][1] == "BENIGN").all():
                continue
            oX = pd.concat([v[0] for d, v in days.items() if d != held])
            oy = pd.concat([v[1] for d, v in days.items() if d != held])
            sX, sy = sample_train(oX, oy, 200_000, 60_000)
            m = rf(50).fit(preprocess(sX, scaler), (sy != "BENIGN").astype(int))
            hX, hy = days[held][0], days[held][1]
            p = m.predict(preprocess(hX, scaler)).astype(bool); a = (hy != "BENIGN").to_numpy()
            fams = {c: float(p[(hy == c).to_numpy()].mean()) for c in hy.unique() if c != "BENIGN"}
            seen = sorted(set(hy.unique()) & set(oy.unique()) - {"BENIGN"})
            lodo[held] = {"attack_recall": float(p[a].mean()), "benign_false_alarm_rate": float(p[~a].mean()),
                          "recall_by_family": fams, "families_also_in_training": seen}
            print(f"  {held:48} recall {p[a].mean():7.2%}  benign FP {p[~a].mean():7.3%}  "
                  f"by family {({k: round(v, 3) for k, v in fams.items()})}  seen-in-train {seen}", flush=True)
        metrics["B_leave_one_day_out"] = lodo

    os.makedirs(args.out, exist_ok=True)
    joblib.dump(model, os.path.join(args.out, "random_forest.pkl"))
    with open(os.path.join(args.out, "label_map.json"), "w", encoding="utf-8") as fh:
        json.dump({str(i): c for i, c in enumerate(CLASSES)}, fh, indent=2)
    with open(os.path.join(args.out, "multiday_metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"\nSaved {args.out}/ (random_forest.pkl, label_map.json, multiday_metrics.json) "
          f"in {time.time() - t0:,.0f}s. Shipped models untouched.", flush=True)


if __name__ == "__main__":
    main()
