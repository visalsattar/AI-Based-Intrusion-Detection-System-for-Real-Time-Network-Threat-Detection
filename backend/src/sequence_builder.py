"""
Sequence construction for the CNN component (OFFLINE architecture
comparison only -- not part of the live RF+AE detection pipeline).

METHODOLOGICAL NOTES (state in Thesis Chapter 6):

1. Temporal proxy. This CICIDS2017 distribution (78-feature ML-ready CSV)
   has no Timestamp, Flow ID, or IP columns. CSV ROW ORDER is used as a
   proxy for temporal order. CICFlowMeter writes flows roughly in the
   order they are finalized, which correlates with -- but is not
   identical to -- capture time. Report as a limitation.

2. Day-file concatenation. If the CSV was built by concatenating per-day
   files, a row-order split is effectively a day-order split: the test
   set may be dominated by the last day's attack classes, and windows
   can straddle day boundaries. Report per-split class distributions.

3. Leakage prevention. Flat rows are split into train/val/test FIRST
   (contiguous, no shuffle), then windows are built independently within
   each split, so no row appears in more than one split. Building all
   overlapping windows first and then randomly splitting them leaks
   (up to window_size - stride shared rows between adjacent windows) and
   is deliberately not used. Verified by
   tests/test_sequence_builder.py::test_no_row_sharing_across_splits.

4. Labeling. Each window's label is the label of its LAST row ("given the
   preceding window_size-1 flows, is the most recent flow an attack").
   "Any attack in window" is a valid alternative with different
   implications.

5. Evaluation subset. Only rows at positions window_size-1 + k*stride
   within each split are scored. The first window_size-1 rows of each
   split, and trailing rows that do not complete a stride, are never
   scored. CNN metrics are therefore NOT computed on the same flows as
   RF/AE metrics. Use last_row_indices() to evaluate RF/AE on the
   identical subset before comparing numbers.
"""
import numpy as np
import pandas as pd
from numpy.lib.stride_tricks import sliding_window_view


def _validate_labels(y: np.ndarray) -> np.ndarray:
    if y.dtype.kind not in "iub":
        if y.dtype.kind == "f" and np.all(np.equal(np.mod(y, 1), 0)):
            y = y.astype(np.int64)
        else:
            raise ValueError(
                f"Labels must be integer-encoded (got dtype {y.dtype}). "
                f"Encode string labels before building sequences."
            )
    return y.astype(np.int64, copy=False)


def last_row_indices(n_samples: int, window_size: int = 100,
                     stride: int = 10) -> np.ndarray:
    """Flat-row indices (within a split) that the CNN windows are scored on."""
    if n_samples < window_size:
        return np.empty(0, dtype=np.int64)
    return np.arange(window_size - 1, n_samples, stride, dtype=np.int64)


def build_windows(X: np.ndarray, y: np.ndarray,
                  window_size: int = 100, stride: int = 10):
    """
    Slide a window across X (must already be in row order for this split;
    do not shuffle before calling). Label of each window = label of its
    last row.

    Returns a READ-ONLY zero-copy view for X_seq, shape
    (n_windows, window_size, n_features). Call np.ascontiguousarray() on
    a batch if a framework needs contiguous memory.
    """
    if window_size < 1 or stride < 1:
        raise ValueError("window_size and stride must be >= 1.")
    n_samples = X.shape[0]
    if n_samples < window_size:
        raise ValueError(
            f"Cannot build sequences of length {window_size} from only "
            f"{n_samples} samples. Reduce window_size, increase data, "
            f"or this split is too small."
        )
    if len(y) != n_samples:
        raise ValueError(f"X has {n_samples} rows but y has {len(y)}.")

    X = np.asarray(X, dtype=np.float32)
    y = _validate_labels(np.asarray(y))

    # sliding_window_view -> (n_windows_full, n_features, window_size)
    X_seq = sliding_window_view(X, window_size, axis=0)[::stride]
    X_seq = X_seq.transpose(0, 2, 1)
    y_seq = y[last_row_indices(n_samples, window_size, stride)]

    assert X_seq.shape[0] == y_seq.shape[0]
    return X_seq, y_seq


def build_cnn_sequences(preprocessed_csv_path: str,
                        window_size: int = 100, stride: int = 10,
                        test_size: float = 0.2, val_size: float = 0.125,
                        min_rows_per_split: int = 200):
    """
    Load preprocessed flat CSV -> split flat rows contiguously (no
    shuffle) -> build windows independently within each split.

    Also returns the flat splits so RF/AE reuse the identical row split,
    and the per-split last-row indices so RF/AE can be scored on the
    same flows as the CNN.
    """
    df = pd.read_csv(preprocessed_csv_path)
    if 'Label' not in df.columns:
        raise ValueError("Expected a 'Label' column in preprocessed data.")

    X_flat = df.drop(columns=['Label']).values.astype(np.float32)
    y_flat = _validate_labels(df['Label'].values)
    n = len(X_flat)

    n_test = int(n * test_size)
    n_trainval = n - n_test
    n_val = int(n_trainval * val_size)
    n_train = n_trainval - n_val

    if min(n_train, n_val, n_test) < max(min_rows_per_split, window_size):
        raise ValueError(
            f"One or more splits too small for reliable windowing: "
            f"train={n_train}, val={n_val}, test={n_test}. "
            f"Need at least {max(min_rows_per_split, window_size)} rows per split."
        )

    splits = {
        'train': (0, n_train),
        'val': (n_train, n_train + n_val),
        'test': (n_train + n_val, n),
    }

    out = {}
    for name, (a, b) in splits.items():
        Xs, ys = X_flat[a:b], y_flat[a:b]
        X_seq, y_seq = build_windows(Xs, ys, window_size, stride)
        out[f'X_seq_{name}'] = X_seq
        out[f'y_seq_{name}'] = y_seq
        out[f'X_{name}_flat'] = Xs
        out[f'y_{name}_flat'] = ys
        out[f'eval_idx_{name}'] = last_row_indices(b - a, window_size, stride)

    return out