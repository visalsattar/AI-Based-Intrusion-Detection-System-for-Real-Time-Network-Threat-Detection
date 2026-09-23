import os
import importlib
from backend.tests.test_inference import BACKEND_DIR


def _load_saved_object(path):
    joblib = importlib.import_module("joblib")
    return joblib.load(path)


def test_feature_scaler_exists_and_has_feature_names():
    BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    path = os.path.join(BACKEND_DIR, 'models', 'feature_scaler.pkl')
    assert os.path.exists(path), "feature_scaler.pkl missing; run preprocessing/training to generate it"
    scaler = _load_saved_object(path)
    assert hasattr(scaler, 'feature_names_in_'), "Saved scaler missing feature_names_in_ attribute"
    assert len(scaler.feature_names_in_) > 0, "Scaler has empty feature_names_in_ — check preprocessing"
