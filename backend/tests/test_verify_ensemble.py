"""verify_ensemble.py's plumbing check must pass on a healthy pipeline AND fail on a broken one."""
import os
import sys

from scapy.all import IP, TCP

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import verify_ensemble as ve  # noqa: E402
from stubs import make_pipeline  # noqa: E402

QUIET = lambda *_: None  # noqa: E731


def test_healthy_pipeline_passes_and_scores_each_flow_once():
    p = make_pipeline()
    ok, results = ve.run_scenarios(p, ve.Tee(), say=QUIET)
    assert ok
    assert [r["scored"] for r in results] == [1, 250, 1]
    assert len(results[1]["alerts"]) == 1, "250 probes from one source must collapse to one alert"
    assert p.flow_tracker == {}


def test_port_scan_cooldown_counts_the_swallowed_alerts(monkeypatch):
    monkeypatch.setattr(ve, "SCENARIOS", [s for s in ve.SCENARIOS if "port scan" in s[0]])
    p = make_pipeline()
    _, results = ve.run_scenarios(p, ve.Tee(), say=QUIET)
    sev = results[0]["alerts"][0]["severity"]
    assert p._last_alert[("45.13.227.7", sev)][1] == 249     # 250 flows, 1 alert, 249 suppressed


def test_check_detects_double_scoring():
    p = make_pipeline()
    original = p._collect_finished_flows
    p._collect_finished_flows = lambda: (lambda ks: ks + ks)(original())   # the bug found in review
    ok, results = ve.run_scenarios(p, ve.Tee(), say=QUIET)
    assert not ok and results[0]["scored"] == 2


def test_check_detects_flows_that_never_finish(monkeypatch):
    """The old script's failure mode: without FIN/RST nothing is ever scored."""
    no_fin = lambda t0: [IP(src="10.0.0.20", dst="93.184.216.34") / TCP(sport=51000, dport=443, flags="S")]  # noqa: E731
    monkeypatch.setattr(ve, "SCENARIOS", [("unfinished flow", no_fin, 1)])
    ok, results = ve.run_scenarios(make_pipeline(), ve.Tee(), say=QUIET)
    assert not ok and results[0]["scored"] == 0


def test_tee_never_exposes_stored_settings():
    assert ve.Tee().get("ids:settings") is None       # UI-saved autoBlock must not leak in
