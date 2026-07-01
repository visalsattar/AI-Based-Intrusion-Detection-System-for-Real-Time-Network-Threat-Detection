"""
Real tests for sequence_builder — the CNN's data preparation.

The single most important property here is the leakage-prevention design
(split flat rows first, then window independently within each split). The
thesis's validity depends on it, so it gets a direct regression test. Also
covers window shape, last-row labelling, and the too-small-split guard.

These use small synthetic data and never touch TensorFlow, so they are
fast and hermetic.
"""
import numpy as np
import pandas as pd
import pytest

from sequence_builder import (
    build_windows,
    build_cnn_sequences,
    _verify_no_window_overlap_across_splits,
)


def test_window_shape_and_count():
    """(n_samples - window_size)//stride + 1 windows, each window_size x n_features."""
    X = np.arange(1000 * 5, dtype=np.float32).reshape(1000, 5)
    y = np.zeros(1000, dtype=np.int64)

    X_seq, y_seq = build_windows(X, y, window_size=100, stride=10)

    expected_n = (1000 - 100) // 10 + 1
    assert X_seq.shape == (expected_n, 100, 5)
    assert y_seq.shape == (expected_n,)


def test_window_preserves_row_order():
    """Window 0 must be exactly the first `window_size` rows, in order."""
    X = np.arange(1000 * 5, dtype=np.float32).reshape(1000, 5)
    y = np.zeros(1000, dtype=np.int64)

    X_seq, _ = build_windows(X, y, window_size=100, stride=10)
    assert np.array_equal(X_seq[0], X[0:100])


def test_last_row_labelling():
    """Each window's label is the label of its LAST row."""
    X = np.arange(1000 * 5, dtype=np.float32).reshape(1000, 5)
    y = np.zeros(1000, dtype=np.int64)
    y[500:510] = 1  # attack rows

    _, y_seq = build_windows(X, y, window_size=100, stride=10)

    # Window index 41 starts at row 410, covers 410..509 -> last row 509 = attack.
    assert y_seq[41] == 1
    # Window 0 covers rows 0..99, all benign.
    assert y_seq[0] == 0


def test_raises_when_split_too_small():
    """Windowing must fail loudly, not silently, when a split is too short."""
    with pytest.raises(ValueError):
        build_windows(np.zeros((50, 5)), np.zeros(50), window_size=100)


def test_no_leakage_between_train_and_test(tmp_path):
    """
    THE critical test: no window in the train split may share all its rows
    with any window in the test split. Regression guard for the leakage bug
    documented in sequence_builder.py.
    """
    rng = np.random.RandomState(42)
    df = pd.DataFrame(rng.rand(3000, 6), columns=[f"f{i}" for i in range(5)] + ["Label"])
    df["Label"] = (df["Label"] > 0.5).astype(int)
    csv = tmp_path / "seq.csv"
    df.to_csv(csv, index=False)

    result = build_cnn_sequences(str(csv), window_size=50, stride=5, min_rows_per_split=100)

    assert _verify_no_window_overlap_across_splits(
        result["X_seq_train"], result["X_seq_test"]
    ), "LEAKAGE: train and test windows share rows"
    assert _verify_no_window_overlap_across_splits(
        result["X_seq_train"], result["X_seq_val"]
    ), "LEAKAGE: train and val windows share rows"
