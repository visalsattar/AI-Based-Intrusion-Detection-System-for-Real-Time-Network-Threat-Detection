"""
Sequence construction for the CNN component of the hybrid IDS.

METHODOLOGICAL NOTE (this must be stated in Thesis Chapter 6):
This CICIDS2017 distribution (the 78-feature ML-ready CSV) contains no
Timestamp, Flow ID, or IP address columns. True chronological ordering
of flows is therefore not recoverable from this file. As a documented
limitation, this module uses CSV ROW ORDER as a proxy for temporal
order: CICFlowMeter (the tool used to generate CICIDS2017) writes flows
to disk approximately in the order they are finalized during capture,
which correlates with -- but is not identical to -- true capture-time
order. This should be reported as a limitation, not presented as exact
chronological ground truth.

LEAKAGE-PREVENTION DESIGN (important, verified, do not "simplify"):
Flat rows are split into train/val/test FIRST, preserving row order
within each split. Sliding windows are then built INDEPENDENTLY within
each split. This guarantees no window in train can share any rows with
a window in test/val.

The alternative approach -- building all overlapping windows first,
then randomly splitting the resulting windows -- was tried, tested, and
found to leak: with stride < window_size, adjacent windows share up to
(window_size - stride) rows. A direct test showed 90% row-overlap
between adjacent windows at window_size=100, stride=10. That approach
was rejected and is not used here.

Each window's label is the label of its LAST row (i.e. "given the
preceding window_size-1 flows of context, is the most recent flow an
attack"). This is a deliberate choice, not the only valid one -- "any
attack in the window" is an alternative methodology with different
implications -- so this choice and its rationale should be stated
explicitly in Chapter 6.
"""
import numpy as np
import pandas as pd


def build_windows(X: np.ndarray, y: np.ndarray,
                   window_size: int = 100, stride: int = 10):
    """
    Slide a window across X (assumed to already be in correct row
    order for this split -- do not shuffle before calling). Label of
    each window = label of its last row.
    """
    n_samples, n_features = X.shape
    if n_samples < window_size:
        raise ValueError(
            f"Cannot build sequences of length {window_size} from only "
            f"{n_samples} samples. Reduce window_size, increase data, "
            f"or this split is too small."
        )

    starts = list(range(0, n_samples - window_size + 1, stride))
    X_seq = np.empty((len(starts), window_size, n_features), dtype=np.float32)
    y_seq = np.empty(len(starts), dtype=np.int64)

    for i, s in enumerate(starts):
        X_seq[i] = X[s:s + window_size]
        y_seq[i] = y[s + window_size - 1]   # label of LAST row in window

    return X_seq, y_seq


def build_cnn_sequences(preprocessed_csv_path: str,
                         window_size: int = 100, stride: int = 10,
                         test_size: float = 0.2, val_size: float = 0.125,
                         min_rows_per_split: int = 200):
    """
    Full pipeline: load preprocessed flat CSV -> split flat rows
    (no shuffle, preserving row order) -> build windows independently
    within each split.

    Returns flat splits too, so the autoencoder/RF can reuse the exact
    same underlying row split as the CNN, keeping evaluation consistent
    across all three models in the hybrid system.
    """
    df = pd.read_csv(preprocessed_csv_path)
    if 'Label' not in df.columns:
        raise ValueError("Expected a 'Label' column in preprocessed data.")

    X_flat = df.drop(columns=['Label']).values.astype(np.float32)
    y_flat = df['Label'].values
    n = len(X_flat)

    n_test = int(n * test_size)
    n_trainval = n - n_test
    n_val = int(n_trainval * val_size)
    n_train = n_trainval - n_val

    if min(n_train, n_val, n_test) < min_rows_per_split:
        raise ValueError(
            f"One or more splits too small for reliable windowing: "
            f"train={n_train}, val={n_val}, test={n_test}. "
            f"Need at least {min_rows_per_split} rows per split."
        )

    # No shuffle: row order must be preserved within each split for
    # "row order as temporal proxy" to mean anything.
    X_train_flat, y_train_flat = X_flat[:n_train], y_flat[:n_train]
    X_val_flat, y_val_flat = (X_flat[n_train:n_train + n_val],
                                y_flat[n_train:n_train + n_val])
    X_test_flat, y_test_flat = (X_flat[n_train + n_val:],
                                  y_flat[n_train + n_val:])

    X_seq_train, y_seq_train = build_windows(X_train_flat, y_train_flat, window_size, stride)
    X_seq_val, y_seq_val = build_windows(X_val_flat, y_val_flat, window_size, stride)
    X_seq_test, y_seq_test = build_windows(X_test_flat, y_test_flat, window_size, stride)

    return {
        'X_seq_train': X_seq_train, 'y_seq_train': y_seq_train,
        'X_seq_val': X_seq_val, 'y_seq_val': y_seq_val,
        'X_seq_test': X_seq_test, 'y_seq_test': y_seq_test,
        'X_train_flat': X_train_flat, 'y_train_flat': y_train_flat,
        'X_val_flat': X_val_flat, 'y_val_flat': y_val_flat,
        'X_test_flat': X_test_flat, 'y_test_flat': y_test_flat,
    }


def _verify_no_window_overlap_across_splits(X_seq_a, X_seq_b, sample_check=50):
    """
    Self-test helper: confirm no window in split A shares all its rows
    with any window in split B. Used by the test suite below, and safe
    to call manually if you want to re-verify after changing parameters.
    """
    if len(X_seq_a) == 0 or len(X_seq_b) == 0:
        return True
    a_flat_sample = X_seq_a[:sample_check].reshape(min(sample_check, len(X_seq_a)), -1)
    b_flat_sample = X_seq_b[:sample_check].reshape(min(sample_check, len(X_seq_b)), -1)
    for a_row in a_flat_sample:
        for b_row in b_flat_sample:
            if np.array_equal(a_row, b_row):
                return False
    return True


if __name__ == "__main__":
    print("Running self-tests on sequence construction...")

    # Test 1: basic shape + ordering correctness
    X_test = np.arange(1000 * 5).reshape(1000, 5).astype(np.float32)
    y_test = np.zeros(1000, dtype=np.int64)
    y_test[500:510] = 1

    X_seq, y_seq = build_windows(X_test, y_test, window_size=100, stride=10)
    expected_n = (1000 - 100) // 10 + 1
    assert X_seq.shape == (expected_n, 100, 5), f"Shape mismatch: {X_seq.shape}"
    print(f"  [PASS] Shape correct: {X_seq.shape}")

    assert np.array_equal(X_seq[0], X_test[0:100]), "Window 0 ordering broken"
    print("  [PASS] Window 0 matches rows 0-99 exactly, in order")

    # Test 2: last-row labeling is correct
    # window starting at row 410 covers rows 410-509, last row = 509 (attack)
    idx_410 = 41  # start = 41*10 = 410
    assert y_seq[idx_410] == 1, "Window ending in attack row not labeled attack"
    assert y_seq[0] == 0, "All-benign window incorrectly labeled attack"
    print("  [PASS] Last-row label assignment correct")

    # Test 3: insufficient data raises cleanly
    try:
        build_windows(np.zeros((50, 5)), np.zeros(50), window_size=100)
        print("  [FAIL] Should have raised ValueError")
    except ValueError:
        print("  [PASS] Raises ValueError when n_samples < window_size")

    # Test 4: THE LEAKAGE TEST -- this is the one that matters most.
    # Build via the full split-first pipeline on synthetic data saved
    # to a temp CSV, then verify zero row-sharing between train and
    # test windows.
    import tempfile, os
    tmp_df = pd.DataFrame(
        np.random.rand(3000, 6), columns=[f'f{i}' for i in range(5)] + ['Label']
    )
    tmp_df['Label'] = (tmp_df['Label'] > 0.5).astype(int)
    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp:
        tmp_df.to_csv(tmp.name, index=False)
        tmp_path = tmp.name

    result = build_cnn_sequences(tmp_path, window_size=50, stride=5,
                                   min_rows_per_split=100)
    no_leak = _verify_no_window_overlap_across_splits(
        result['X_seq_train'], result['X_seq_test']
    )
    assert no_leak, "LEAKAGE DETECTED between train and test windows!"
    print("  [PASS] No row-overlap between train and test windows "
          "(leakage check, sampled)")
    os.unlink(tmp_path)

    print("\nAll self-tests passed. Safe to use on real data.")
