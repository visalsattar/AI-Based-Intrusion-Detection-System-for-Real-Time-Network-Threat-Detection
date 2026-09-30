import json

from stubs import make_pipeline


def test_real_alert_path_writes_to_redis_stream():
    pipeline = make_pipeline()
    flow_key = (("8.8.4.4", 4444), ("10.0.0.5", 80), 6)
    from datetime import datetime
    now = datetime.now()
    pipeline.flow_tracker[flow_key] = {
        "packets": 2, "bytes": 100, "first_seen": now, "last_seen": now,
        "protocol": 6, "packet_list": [], "init_src": "8.8.4.4", "init_sport": 4444,
        "init_dst": "10.0.0.5", "init_dport": 80, "fwd_win": 0, "bwd_win": 0,
        "done": True, "init_syn": True,
    }
    pipeline._process_prediction(flow_key, recon_error=1.0, rf_attack_prob=None)
    assert len(pipeline.redis_client.calls) == 1
    stream, mapping, _ = pipeline.redis_client.calls[0]
    assert stream == "ids:alerts"
    assert json.loads(mapping["data"])["src_ip"] == "8.8.4.4"
