"""
Real tests for data_preprocessing.CICIDSPreprocessor.

These replace the earlier scaffold and implement the cases described in
its docstring: infinite-value handling, MinMax range, label binarisation,
and confirmation that the Label column is never scaled. They run on small
synthetic CSVs (no real dataset needed), so they are fast and hermetic.
"""
import numpy as np
import pandas as pd
import pytest

from data_preprocessing import CICIDSPreprocessor


def _write_csv(tmp_path, df):
    path = tmp_path / "raw.csv"
    df.to_csv(path, index=False)
    return str(path)


def _sample_frame():
    # Two numeric feature columns + a text Label, mixing BENIGN and an attack.
    return pd.DataFrame(
        {
            "Flow Duration": [100.0, 200.0, 300.0, 400.0],
            "Flow Bytes/s": [10.0, 20.0, 30.0, 40.0],
            "Label": ["BENIGN", "DDoS", "BENIGN", "PortScan"],
        }
    )


def test_infinite_values_are_removed(tmp_path):
    """An inf in a feature column must not survive preprocessing."""
    df = _sample_frame()
    df.loc[1, "Flow Bytes/s"] = np.inf
    out = CICIDSPreprocessor().preprocess_pipeline(_write_csv(tmp_path, df))

    feature_cols = [c for c in out.columns if c != "Label"]
    assert np.isfinite(out[feature_cols].to_numpy()).all(), "inf/-inf leaked through preprocessing"


def test_minmax_range(tmp_path):
    """All scaled feature columns must fall within [0.0, 1.0]."""
    out = CICIDSPreprocessor().preprocess_pipeline(_write_csv(tmp_path, _sample_frame()))

    feature_cols = [c for c in out.columns if c != "Label"]
    arr = out[feature_cols].to_numpy()
    assert arr.min() >= 0.0 - 1e-9, f"feature below 0 after MinMax: {arr.min()}"
    assert arr.max() <= 1.0 + 1e-9, f"feature above 1 after MinMax: {arr.max()}"


def test_label_binarised_and_not_scaled(tmp_path):
    """BENIGN -> 0, any attack -> 1, and Label values stay exactly {0,1}."""
    out = CICIDSPreprocessor().preprocess_pipeline(_write_csv(tmp_path, _sample_frame()))

    assert "Label" in out.columns
    assert set(np.unique(out["Label"])).issubset({0, 1}), "Label was not binarised to {0,1}"
    # BENIGN rows were indices 0 and 2 in the input; they must be class 0.
    assert out["Label"].iloc[0] == 0 and out["Label"].iloc[2] == 0
    # Attack rows (1 = DDoS, 3 = PortScan) must be class 1.
    assert out["Label"].iloc[1] == 1 and out["Label"].iloc[3] == 1


def test_object_columns_dropped(tmp_path):
    """Non-numeric columns (e.g. an IP address) must be dropped, not scaled."""
    df = _sample_frame()
    df["Source IP"] = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    out = CICIDSPreprocessor().preprocess_pipeline(_write_csv(tmp_path, df))

    assert "Source IP" not in out.columns, "text column survived preprocessing"
