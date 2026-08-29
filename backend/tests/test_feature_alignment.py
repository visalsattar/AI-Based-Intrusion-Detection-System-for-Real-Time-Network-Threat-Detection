import os
from joblib import load


def test_feature_scaler_exists_and_has_feature_names():
    path = os.path.join('backend', 'models', 'feature_scaler.pkl')
    assert os.path.exists(path), "feature_scaler.pkl missing; run preprocessing/training to generate it"
    scaler = load(path)
    assert hasattr(scaler, 'feature_names_in_'), "Saved scaler missing feature_names_in_ attribute"
    assert len(scaler.feature_names_in_) > 0, "Scaler has empty feature_names_in_ — check preprocessing"
