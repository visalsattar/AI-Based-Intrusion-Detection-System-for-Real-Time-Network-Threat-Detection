# backend/src/redis_alert_bridge.py
"""
Redis -> Socket.IO Alert Bridge.

This is the piece that was missing in main.py before: RealTimeIDSPipeline
(ids_pipeline.py) already writes detected intrusions to the Redis stream
'ids:alerts' (see _process_prediction's redis_client.xadd call). But nothing
was tailing that stream and pushing it out over the WebSocket — so the
React dashboard's socket connected fine, but no 'new_alert' events ever
arrived once you switched off mock mode.

This module tails the stream from wherever it left off and emits each new
entry as a 'new_alert' Socket.IO event, enriching with GeoIP location the
same way the mock generator does, so AlertTable / Dashboard / ThreatIntel
behave identically regardless of which alert source is active.

Use this INSTEAD of mock_alert_generator.py once `--mode ids` (or any
process writing to the same Redis stream) is actually running. Toggle via
the MOCK_ALERTS env var in main.py — when MOCK_ALERTS=false, this bridge
starts instead of the mock stream.
"""

import json
import logging

from geo_utils import get_ip_location

logger = logging.getLogger("IDS-RedisBridge")


def start_redis_alert_bridge(socketio, redis_client, stream_key="ids:alerts", block_ms=1000):
    """
    Background task entrypoint. Call via:
        socketio.start_background_task(start_redis_alert_bridge, socketio, redis_client)

    Blocks (cooperatively, under eventlet) on XREAD against `stream_key` and
    emits every new entry as it arrives. Safe to leave running indefinitely;
    reconnects on transient Redis errors instead of dying.
    """
    if not redis_client:
        logger.warning("No Redis connection available — alert bridge cannot start. "
                        "Live alerts from the real pipeline will not reach the dashboard "
                        "until Redis is reachable.")
        return

    logger.info(f"Redis alert bridge started — tailing '{stream_key}' for live intrusions.")
    last_id = "$"  # "$" = only new entries from this point forward, not history

    while True:
        try:
            # block_ms blocks this greenthread cooperatively (eventlet patches
            # the socket module), so other Socket.IO clients/background tasks
            # keep running normally while this waits for new data.
            result = redis_client.xread({stream_key: last_id}, count=10, block=block_ms)
            if not result:
                continue

            for _stream_name, messages in result:
                for msg_id, fields in messages:
                    last_id = msg_id
                    try:
                        alert = json.loads(fields["data"])
                    except (KeyError, json.JSONDecodeError) as e:
                        logger.warning(f"Skipping malformed stream entry {msg_id}: {e}")
                        continue

                    alert.setdefault("location", get_ip_location(alert.get("src_ip")))
                    socketio.emit("new_alert", alert)

        except Exception as e:
            logger.error(f"Redis alert bridge error (will retry): {e}")
            socketio.sleep(2)
