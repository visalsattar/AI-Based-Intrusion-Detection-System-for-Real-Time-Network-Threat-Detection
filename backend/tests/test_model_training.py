"""
STATUS: Scaffolded but not completed (see Thesis Chapter 7.3 / 8.2).

The real training pipeline (main.py -> train_models()) was run
end-to-end against the full real CICIDS2017 dataset and produced the
verified metrics in models/real_metrics.json (see src/model_evaluation.py
to reproduce). This file is the placeholder for converting that
verified run into a repeatable automated test.

Suggested cases to implement:
  - test_no_train_test_leakage(): assert zero row-overlap between
    sequence windows in train vs test splits (regression test for the
    leakage bug found and fixed in an earlier sequence-building
    approach during this development cycle -- see sequence_builder.py
    docstring for the full history).
  - test_autoencoder_trains_on_benign_only(): assert the autoencoder's
    training data contains only Label == 0 rows.
  - test_cnn_not_trained_on_noise(): assert CNN training input has
    nonzero correlation with the real feature data (regression test
    for the np.random.randn bug fixed during this development cycle).
"""
import pytest

def test_placeholder():
    pytest.skip("Not yet implemented -- see module docstring for planned cases")
