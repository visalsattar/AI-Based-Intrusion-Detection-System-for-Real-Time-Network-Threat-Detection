"""
STATUS: Scaffolded but not completed

Manual verification confirmed the real end-to-end alert path (a
constructed alert pushed to Redis correctly arrives at the React
dashboard via WebSocket), and confirmed feature extraction in
ids_pipeline.py produces correct values against deliberately
constructed Scapy packets (see project development notes). This file
is the placeholder for converting that into a real, automated suite.

Suggested cases to implement:
  - test_feature_extraction_known_packets(): build a flow from known
    Scapy packets, assert _extract_flow_features() returns the exact
    expected values for duration, packet count, IAT stats, flag counts.
  - test_threshold_gating(): assert _process_prediction() only emits
    an alert when anomaly_score > self.alert_threshold (regression
    test for the "if True:" hack fixed during this development cycle).
  - test_severity_levels(): assert _compute_severity() returns the
    correct label for scores at each boundary (0.65, 0.85, 0.95).
"""
import pytest

def test_placeholder():
    pytest.skip("Not yet implemented -- see module docstring for planned cases")
