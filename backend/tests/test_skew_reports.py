import os
import sys

import numpy as np
import pandas as pd
import pytest
from sklearn.preprocessing import MinMaxScaler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))
import skew_report  # noqa: E402


def _scaler_and_live(n=200, seed=0):
    rng = np.random.default_rng(seed)
    train = pd.DataFrame({"Total Length of Fwd Packets": rng.integers(0, 500, 1000).astype(float),
                          "Flow Duration": rng.uniform(0, 1e6, 1000),
                          "Idle Mean": rng.uniform(0, 1e5, 1000)})
    train.iloc[0] = 0.0          # CICIDS minimums are 0 for these columns
    sc = MinMaxScaler().fit(train)
    live = pd.DataFrame({
        "Total Length of Fwd Packets": rng.integers(40, 5000, n).astype(float),   # header-inflated + big
        "Flow Duration": rng.uniform(0, 1e6, n),                                  # well-behaved
        "Idle Mean": np.zeros(n),                                                 # never measured
        "recon_error": np.r_[np.full(n - 10, 0.001), np.full(10, 0.5)],
        "rf_prob": np.r_[np.zeros(n - 4), np.ones(4)],
    })
    return sc, live


def test_flags_the_skewed_feature_and_leaves_the_healthy_one_alone():
    sc, live = _scaler_and_live()
    r = skew_report.build_report(live, sc, threshold=0.003)
    f = r["features"].set_index("feature")
    assert f.loc["Total Length of Fwd Packets", "above_train_max"] > 0.8
    assert f.loc["Flow Duration", "out_of_range"] < 0.05
    assert r["worst"].iloc[0].feature == "Total Length of Fwd Packets"
    assert r["always_zero_live"] == ["Idle Mean"]


def test_ae_and_rf_shares():
    sc, live = _scaler_and_live(n=200)
    r = skew_report.build_report(live, sc, threshold=0.003)
    assert r["share_above_threshold"] == pytest.approx(10 / 200)
    assert r["share_ae_override"] == pytest.approx(10 / 200)      # 0.5 >> 0.003*32.3
    assert r["rf"]["gt_0.9"] == pytest.approx(4 / 200)


def test_missing_columns_fail_loudly():
    sc, live = _scaler_and_live()
    with pytest.raises(SystemExit):
        skew_report.build_report(live.drop(columns=["Flow Duration"]), sc)


def test_cli_end_to_end(tmp_path, capsys):
    import joblib
    sc, live = _scaler_and_live()
    live.to_csv(tmp_path / "live.csv", index=False)
    joblib.dump(sc, tmp_path / "s.pkl")
    assert skew_report.main([str(tmp_path / "live.csv"), "--scaler", str(tmp_path / "s.pkl"),
                             "--metrics", str(tmp_path / "none.json"), "--threshold", "0.003"]) == 0
    out = capsys.readouterr().out
    assert "Total Length of Fwd Packets" in out and "ALWAYS 0 LIVE" in out and "AE-override level" in out
