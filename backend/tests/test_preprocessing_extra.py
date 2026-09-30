"""Regression tests for bugs found in review of data_preprocessing.py / logging setup."""
import json
import os
import subprocess
import sys

import joblib
import numpy as np
import pandas as pd

from data_preprocessing import CICIDSPreprocessor

CICIDS_ATTACKS = ["Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
                  "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator",
                  "Web Attack Brute Force", "Web Attack Sql Injection", "Web Attack XSS"]   # the 14 real ones


def _backend(tmp_path):
    (tmp_path / "data" / "preprocessed").mkdir(parents=True)
    return tmp_path


def _frame(labels):
    n = len(labels)
    return pd.DataFrame({"f1": np.arange(n, dtype=float), "f2": np.arange(n)[::-1].astype(float), "Label": labels})


def test_multiclass_integers_match_label_map_for_all_14_attack_classes(tmp_path):
    """LabelEncoder over already-integer labels re-sorted them as strings: 13 of 15 mismatched."""
    b = _backend(tmp_path)
    labels = ["BENIGN"] + CICIDS_ATTACKS
    raw = b / "raw.csv"
    _frame(labels).to_csv(raw, index=False)
    out = CICIDSPreprocessor().preprocess_pipeline(
        str(raw), output_path=str(b / "data" / "preprocessed" / "x.csv"), multiclass=True)

    label_map = {int(k): v for k, v in json.load(open(b / "models" / "label_map.json")).items()}
    for name, stored in zip(labels, out["Label"].tolist()):
        assert label_map[stored].lower() == name.lower(), f"{name} stored as {stored} = {label_map[stored]}"


def test_label_map_lands_in_backend_models_not_data_models(tmp_path):
    b = _backend(tmp_path)
    _frame(["BENIGN", "DDoS", "PortScan", "BENIGN"]).to_csv(b / "raw.csv", index=False)
    CICIDSPreprocessor().preprocess_pipeline(
        str(b / "raw.csv"), output_path=str(b / "data" / "preprocessed" / "x.csv"), multiclass=True)
    assert (b / "models" / "label_map.json").exists()
    assert not (b / "data" / "models").exists()


def test_binary_labels_unchanged(tmp_path):
    b = _backend(tmp_path)
    _frame(["BENIGN", "DDoS", "PortScan", "BENIGN"]).to_csv(b / "raw.csv", index=False)
    out = CICIDSPreprocessor().preprocess_pipeline(str(b / "raw.csv"))
    assert out["Label"].tolist() == [0, 1, 1, 0]


def test_scaler_is_saved_with_feature_names_and_never_silently_overwritten(tmp_path):
    b = _backend(tmp_path)
    _frame(["BENIGN", "DDoS", "BENIGN", "DDoS"]).to_csv(b / "raw.csv", index=False)
    target = str(b / "models" / "feature_scaler.pkl")

    CICIDSPreprocessor().preprocess_pipeline(str(b / "raw.csv"), scaler_path=target)
    sc = joblib.load(target)
    assert list(sc.feature_names_in_) == ["f1", "f2"]              # features only, never 'Label'

    before = os.path.getmtime(target)
    CICIDSPreprocessor().preprocess_pipeline(str(b / "raw.csv"), scaler_path=target)
    assert os.path.getmtime(target) == before, "the deployed scaler was overwritten"
    assert os.path.exists(str(b / "models" / "feature_scaler.new.pkl"))

    CICIDSPreprocessor().preprocess_pipeline(str(b / "raw.csv"), scaler_path=target, overwrite_scaler=True)
    assert os.path.getmtime(target) > before


def test_importing_library_modules_does_not_configure_logging():
    """
    A logging.basicConfig() at import time pre-empts main.py's own setup, which then silently does
    nothing -- logs/ids.log stayed 0 bytes. Library modules must leave the root logger alone.
    """
    src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
    code = ("import sys, logging; sys.path.insert(0, %r); "
            "import data_preprocessing, ids_pipeline; "
            "print(len(logging.getLogger().handlers))" % src)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "0", f"importing configured logging: {out.stdout!r}"
