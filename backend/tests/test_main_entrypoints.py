"""End-to-end checks of main.py's real handlers (not extracted helper logic).

test_status_bridge_auth.py covers socket_authorized() and test_model_artifacts.py covers
missing_live_artifacts() in isolation. These run the actual Socket.IO connect handler and
run_ids_capture() so a wiring regression (helper no longer called, wrong env var, early
return removed) fails a test. Each runs in a subprocess: importing main builds the Flask app,
Redis client and logging at module level, which must not leak into the rest of the suite.
"""
import json
import os
import subprocess
import sys
import tempfile

BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _run_main_script(body, **env):
    script = "import sys, json; sys.argv=['main.py','--mode','ids']; import main\n" + body
    r = subprocess.run(
        [sys.executable, "-c", script], cwd=BACKEND, capture_output=True, text=True, timeout=180,
        env={**os.environ, "REDIS_HOST": "127.0.0.1", "REDIS_PORT": "1",
             "TF_CPP_MIN_LOG_LEVEL": "3", "IDS_LOG_DIR": tempfile.mkdtemp(prefix="ids_test_logs_"),
             **env},
    )
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


_SOCKET_PROBE = """
main.socketio.start_background_task = lambda *a, **k: None   # no Redis bridge
def ok(auth, host='localhost:5000'):
    return main.socketio.test_client(main.app, auth=auth, headers={'Host': host}).is_connected()
print(json.dumps({
    'none': ok(None), 'empty': ok({}), 'wrong': ok({'token': 'nope'}),
    'non_str': ok({'token': 123}), 'right': ok({'token': 's3cret'}),
    'right_bad_host': ok({'token': 's3cret'}, host='evil.example:5000'),
}))
"""


def test_socket_connect_handler_enforces_token_and_host():
    res = _run_main_script(_SOCKET_PROBE, IDS_API_TOKEN="s3cret")
    assert res == {"none": False, "empty": False, "wrong": False, "non_str": False,
                   "right": True, "right_bad_host": False}


def test_socket_connect_handler_open_without_token_on_loopback():
    res = _run_main_script(_SOCKET_PROBE, IDS_API_TOKEN="")
    assert res["none"] is True and res["right_bad_host"] is False


_CAPTURE_PROBE = """
import os, tempfile
d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, 'models'))
for n in ('autoencoder.h5', 'feature_scaler.pkl'):          # RF deliberately missing
    open(os.path.join(d, 'models', n), 'wb').write(b'x')
main.BASE_DIR = d
main.resolve_interface = lambda i: i
built = []
main.RealTimeIDSPipeline = lambda *a, **k: built.append(1)
main.run_ids_capture('eth-test')
print(json.dumps({'pipeline_built': bool(built)}))
"""


def test_run_ids_capture_refuses_without_random_forest():
    assert _run_main_script(_CAPTURE_PROBE, IDS_AE_ONLY_ALERTING_VALIDATED="false") == \
        {"pipeline_built": False}


def test_run_ids_capture_proceeds_without_rf_only_when_ae_only_validated():
    assert _run_main_script(_CAPTURE_PROBE, IDS_AE_ONLY_ALERTING_VALIDATED="true") == \
        {"pipeline_built": True}
