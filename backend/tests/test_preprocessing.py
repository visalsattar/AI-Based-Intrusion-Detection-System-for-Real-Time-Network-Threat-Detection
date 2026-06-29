"""
STATUS: Scaffolded but not completed (see Thesis Chapter 7.3 / 8.2).

Manual verification of data_preprocessing.py was performed directly
against the real CICIDS2017 capture during development (confirmed:
NaN/Inf rows correctly identified and dropped, MinMaxScaler correctly
fit on training data only, no double-scaling). This file is the
placeholder for converting that manual verification into a real,
automated pytest suite.

Suggested cases to implement:
  - test_drops_inf_rows(): inject a row with Flow Bytes/s = inf, assert
    it is removed and the row count decreases by exactly 1.
  - test_no_double_scaling(): assert normalize_features() is called
    exactly once per preprocess_pipeline() run (regression test for
    the double-scaling bug fixed during this development cycle).
  - test_minmax_range(): assert all output feature columns fall in
    [0.0, 1.0] after scaling.
  - test_label_not_leaked(): assert 'Label' column values are never
    scaled (i.e. remain exactly 0 or 1 after normalize_features()).
"""
import pytest

def test_placeholder():
    pytest.skip("Not yet implemented -- see module docstring for planned cases")
