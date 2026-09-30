# backend/src/redis_alert_bridge.py
"""
Redis -> Socket.IO alert bridge.

Tails the 'ids:alerts' stream written by RealTimeIDSPipeline and emits each entry
as a 'new_alert' event, enriched with GeoIP location.

Alerts are emitted ONLY to the ALERT_ROOM. main.py adds a socket to that room after
it passes authentication, so an unauthenticated client that connects receives nothing.

Delivery semantics: live push is best-effort. The bridge starts at "$" (new entries
only), so alerts written while the dashboard process is down are not pushed; they
are still in the stream and served by the history REST endpoint.
"""

import json
import logging

from geo_utils import get_ip_location

logger = logging.getLogger("IDS-RedisBridge")

ALERT_ROOM = "alerts"


def start_redis_alert_bridge(socketio, redis_client, stream_key="ids:alerts", block_ms=1000):
    """
    Background task entrypoint:
        socketio.start_background_task(start_redis_alert_bridge, socketio, redis_client)
    Reconnects on transient Redis errors (with backoff) instead of dying.
    """
    if not redis_client:
        logger.warning("No Redis client — alert bridge cannot start; live alerts will not "
                       "reach the dashboard.")
        return

    logger.info(f"Redis alert bridge started — tailing '{stream_key}' (room '{ALERT_ROOM}').")
    last_id = "$"
    backoff = 1

    while True:
        try:
            result = redis_client.xread({stream_key: last_id}, count=50, block=block_ms)
            backoff = 1
            if not result:
                continue

            for _stream_name, messages in result:
                for msg_id, fields in messages:
                    last_id = msg_id
                    raw = fields.get("data") if isinstance(fields, dict) else None
                    if raw is None and isinstance(fields, dict):
                        raw = fields.get(b"data")       # decode_responses=False clients
                    try:
                        alert = json.loads(raw)
                        if not isinstance(alert, dict):
                            raise ValueError("payload is not an object")
                    except (TypeError, ValueError) as e:
                        logger.warning(f"Skipping malformed stream entry {msg_id}: {e}")
                        continue

                    try:
                        alert.setdefault("location", get_ip_location(alert.get("src_ip")))
                    except Exception as e:
                        logger.debug(f"GeoIP lookup failed for {alert.get('src_ip')}: {e}")
                        alert.setdefault("location", None)
                    socketio.emit("new_alert", alert, to=ALERT_ROOM)

        except Exception as e:
            logger.error(f"Redis alert bridge error (retry in {backoff}s): {e}")
            socketio.sleep(backoff)
            backoff = min(backoff * 2, 30)