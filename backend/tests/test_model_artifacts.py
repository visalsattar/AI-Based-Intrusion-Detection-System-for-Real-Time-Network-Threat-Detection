"""Tests for the live-capture artifact preflight (backend/src/model_artifacts.py)."""
import os
import sys

_BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (_BACKEND, os.path.join(_BACKEND, "src")):
    if p not in sys.path:
        sys.path.insert(0, p)

import pytest

from model_artifacts import (
    AUTOENCODER, RANDOM_FOREST, SCALER,
    ae_only_alerting_validated, missing_live_artifacts,
)


def make(models_dir, *names):
    for n in names:
        (models_dir / n).write_bytes(b"x")


def test_all_present_ok(tmp_path):
    make(tmp_path, AUTOENCODER, SCALER, RANDOM_FOREST)
    assert missing_live_artifacts(str(tmp_path), ae_only_validated=False) == []


def test_missing_rf_blocks_by_default(tmp_path):
    make(tmp_path, AUTOENCODER, SCALER)
    assert missing_live_artifacts(str(tmp_path), ae_only_validated=False) == [
        os.path.join(str(tmp_path), RANDOM_FOREST)
    ]


def test_missing_rf_allowed_when_ae_only_validated(tmp_path):
    make(tmp_path, AUTOENCODER, SCALER)
    assert missing_live_artifacts(str(tmp_path), ae_only_validated=True) == []


def test_ae_and_scaler_always_required(tmp_path):
    missing = missing_live_artifacts(str(tmp_path), ae_only_validated=True)
    assert {os.path.basename(p) for p in missing} == {AUTOENCODER, SCALER}


def test_directory_named_like_artifact_does_not_count(tmp_path):
    make(tmp_path, AUTOENCODER, SCALER)
    (tmp_path / RANDOM_FOREST).mkdir()
    assert missing_live_artifacts(str(tmp_path), ae_only_validated=False) == [
        os.path.join(str(tmp_path), RANDOM_FOREST)
    ]


@pytest.mark.parametrize("value,expected", [
    ("true", True), ("TRUE", True), (" yes ", True), ("1", True),
    ("false", False), ("0", False), ("", False), ("no", False),
])
def test_ae_only_flag_parsing(value, expected):
    assert ae_only_alerting_validated({"IDS_AE_ONLY_ALERTING_VALIDATED": value}) is expected


def test_ae_only_flag_defaults_false():
    assert ae_only_alerting_validated({}) is False