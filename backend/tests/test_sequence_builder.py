# backend/tests/test_sequence_builder.py
import numpy as np
import pandas as pd
import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sequence_builder import build_windows, build_cnn_sequences


def _write_csv(tmp_path, df, name="d.csv"):
    p = tmp_path / name
    df.to_csv(p, index=False)
    return str(p)


def test_window_shape():
    X = np.arange(1000 * 5, dtype=np.float32).reshape(1000, 5)
    y = np.zeros(1000, dtype=np.int64)
    X_seq, y_seq = build_windows(X, y, window_size=100, stride=10)
    assert X_seq.shape == ((1000 - 100) // 10 + 1, 100, 5)
    assert y_seq.shape == (X_seq.shape[0],)


def test_window_order_preserved():
    X = np.arange(1000 * 5, dtype=np.float32).reshape(1000, 5)
    y = np.zeros(1000, dtype=np.int64)
    X_seq, _ = build_windows(X, y, window_size=100, stride=10)
    assert np.array_equal(X_seq[0], X[0:100])
    assert np.array_equal(X_seq[1], X[10:110])


def test_last_row_labeling():
    X = np.zeros((1000, 5), dtype=np.float32)
    y = np.zeros(1000, dtype=np.int64)
    y[509] = 1
    _, y_seq = build_windows(X, y, window_size=100, stride=10)
    assert y_seq[41] == 1   # window 410..509, last row is attack
    assert y_seq[40] == 0   # window 400..499, attack not last
    assert y_seq[0] == 0


def test_attack_not_in_last_row_is_benign():
    X = np.zeros((200, 3), dtype=np.float32)
    y = np.zeros(200, dtype=np.int64)
    y[50] = 1               # inside window 0..99 but not last
    _, y_seq = build_windows(X, y, window_size=100, stride=100)
    assert y_seq[0] == 0


def test_too_few_samples_raises():
    with pytest.raises(ValueError):
        build_windows(np.zeros((50, 5)), np.zeros(50), window_size=100)


def test_missing_label_column_raises(tmp_path):
    p = _write_csv(tmp_path, pd.DataFrame({'f1': np.zeros(10)}))
    with pytest.raises(ValueError, match="Label"):
        build_cnn_sequences(p)


def test_split_too_small_raises(tmp_path):
    df = pd.DataFrame({'f1': np.zeros(300), 'Label': np.zeros(300, dtype=int)})
    p = _write_csv(tmp_path, df)
    with pytest.raises(ValueError):
        build_cnn_sequences(p, window_size=10, stride=1, min_rows_per_split=200)


def test_no_row_sharing_across_splits(tmp_path):
    n = 3000
    df = pd.DataFrame({'row_id': np.arange(n, dtype=float),
                       'f1': np.random.default_rng(0).random(n),
                       'Label': np.zeros(n, dtype=int)})
    p = _write_csv(tmp_path, df)
    r = build_cnn_sequences(p, window_size=50, stride=5, min_rows_per_split=100)
    ids = {k: set(r[f'X_seq_{k}'][:, :, 0].ravel().astype(int))
           for k in ('train', 'val', 'test')}
    assert ids['train'].isdisjoint(ids['test'])
    assert ids['train'].isdisjoint(ids['val'])
    assert ids['val'].isdisjoint(ids['test'])


def test_splits_are_contiguous_and_ordered(tmp_path):
    n = 3000
    df = pd.DataFrame({'row_id': np.arange(n, dtype=float),
                       'Label': np.zeros(n, dtype=int)})
    p = _write_csv(tmp_path, df)
    r = build_cnn_sequences(p, window_size=50, stride=5, min_rows_per_split=100)
    tr, va, te = (r[f'X_{k}_flat'][:, 0] for k in ('train', 'val', 'test'))
    assert len(tr) + len(va) + len(te) == n
    assert tr.max() < va.min() and va.max() < te.min()   # train < val < test in row order
    assert np.all(np.diff(np.concatenate([tr, va, te])) == 1)  # no shuffle, no gaps


def test_flat_splits_match_windows(tmp_path):
    n = 3000
    df = pd.DataFrame({'row_id': np.arange(n, dtype=float),
                       'Label': np.zeros(n, dtype=int)})
    p = _write_csv(tmp_path, df)
    r = build_cnn_sequences(p, window_size=50, stride=5, min_rows_per_split=100)
    for k in ('train', 'val', 'test'):
        win_ids = set(r[f'X_seq_{k}'][:, :, 0].ravel().astype(int))
        flat_ids = set(r[f'X_{k}_flat'][:, 0].astype(int))
        assert win_ids <= flat_ids   # windows only use rows from their own split