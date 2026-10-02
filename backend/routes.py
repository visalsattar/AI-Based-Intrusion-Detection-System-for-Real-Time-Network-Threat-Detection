# backend/routes.py
import hmac
import json
import logging
import os
from collections import defaultdict
from time import sleep as _sleep
from urllib.parse import urlparse

from flask import jsonify, request
import psutil
from redis.exceptions import RedisError

from geo_utils import get_ip_location, reload_reader
import geo_utils
from network_utils import list_interfaces, list_arp_devices
from system_status import get_full_status
import threat_intel_service

logger = logging.getLogger("IDS-Routes")

DEFAULT_SETTINGS = {
    "sensitivity": "medium",
    "networkInterface": "auto",
    "flowTimeout": 120,
    "sound": True,
    "desktopNotifications": True,
    "geolocationEnabled": True,
    "threatIntelEnabled": True,
    "autoBlock": False,
    "criticalThreshold": 0.95,
    "highThreshold": 0.85,
}

# Errors worth retrying: Redis down/timeout (redis-py raises RedisError subclasses; raw socket
# failures surface as OSError). Anything else -- e.g. corrupt JSON -- will not fix itself.
_TRANSIENT_ERRORS = (RedisError, OSError)


def allowed_origins() -> list:
    """Browser origins allowed to call the mutating API and to open the Socket.IO channel."""
    raw = os.environ.get(
        "IDS_ALLOWED_ORIGINS",
        "http://localhost:5000,http://127.0.0.1:5000,http://localhost:3000,http://127.0.0.1:3000",
    )
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


def allowed_hosts() -> set:
    """
    Host names the API answers to. This is the DNS-rebinding defence: a hostile page whose domain
    re-resolves to 127.0.0.1 still sends its own domain in the Host header, so it is rejected here.
    Loopback names, every host in IDS_ALLOWED_ORIGINS, and anything in IDS_ALLOWED_HOSTS
    (comma-separated, e.g. the LAN IP you open the dashboard on) are accepted.
    """
    hosts = {"localhost", "127.0.0.1", "::1"}
    for origin in allowed_origins():
        name = urlparse(origin).hostname
        if name:
            hosts.add(name.lower())
    for h in os.environ.get("IDS_ALLOWED_HOSTS", "").split(","):
        h = h.strip().strip("[]").lower()
        if h:
            hosts.add(h)
    return hosts


def _request_hostname():
    return urlparse("//" + (request.host or "")).hostname


def _num(lo, hi, cast):
    def check(v):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError("must be a number")
        v = cast(v)
        if not lo <= v <= hi:
            raise ValueError(f"must be between {lo} and {hi}")
        return v
    return check


def _flag(v):
    if not isinstance(v, bool):
        raise ValueError("must be true or false")
    return v


def _text(max_len):
    def check(v):
        if not isinstance(v, str) or len(v) > max_len:
            raise ValueError(f"must be a string of at most {max_len} characters")
        return v
    return check


def _enum(*allowed):
    def check(v):
        if v not in allowed:
            raise ValueError(f"must be one of {', '.join(allowed)}")
        return v
    return check


# Allow-list. Anything not in here is dropped instead of being written to Redis (the UI also
# posts read-only fields such as abuseIPDBKeySet -- those are simply ignored, not rejected).
SETTINGS_SCHEMA = {
    "sensitivity": _enum("low", "medium", "high"),
    "networkInterface": _text(128),
    "flowTimeout": _num(10, 600, int),
    "sound": _flag,
    "desktopNotifications": _flag,
    "geolocationEnabled": _flag,
    "threatIntelEnabled": _flag,
    "autoBlock": _flag,
    "criticalThreshold": _num(0.80, 0.999, float),
    "highThreshold": _num(0.50, 0.95, float),
}


def startup_auth_error(bind: str, token: str, allow_unauthenticated: bool):
    """
    Fail-closed check run before the server starts. Returns an error string, or None.

    A non-loopback bind with no IDS_API_TOKEN would let anything that can reach the
    port switch on firewall AutoBlock or wipe the alert history (non-browser clients
    send no Origin header, so the Origin check does not stop them). The only way to
    run like that is the explicit IDS_ALLOW_UNAUTHENTICATED=true opt-out, meant for a
    container whose port is published on host loopback only.

    Note: the token guards state-changing requests only. GET routes (alerts, ARP table,
    threat intel, system info) remain readable by anything that can reach the port.
    """
    import ipaddress
    host = (bind or "").strip().strip("[]")
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if loopback or token or allow_unauthenticated:
        return None
    return (f"Refusing to start: IDS_BIND={bind!r} is not loopback and IDS_API_TOKEN is unset. "
            "Set IDS_API_TOKEN, bind to 127.0.0.1, or (container published on host "
            "loopback only) set IDS_ALLOW_UNAUTHENTICATED=true.")


def enforce_startup_auth(env=None) -> None:
    """Refuse to start when the dashboard would be reachable without authentication.
    Reads IDS_BIND / IDS_API_TOKEN / IDS_ALLOW_UNAUTHENTICATED from env (default os.environ)."""
    env = os.environ if env is None else env
    err = startup_auth_error(
        env.get("IDS_BIND", "127.0.0.1"),
        env.get("IDS_API_TOKEN", ""),
        env.get("IDS_ALLOW_UNAUTHENTICATED", "false").strip().lower() in {"1", "true", "yes"},
    )
    if err:
        logging.getLogger("IDS-Orchestrator").error(err)
        raise SystemExit(1)


def validate_settings(incoming: dict):
    """Returns (clean, errors). Keys outside SETTINGS_SCHEMA are ignored."""
    clean, errors = {}, []
    for key, check in SETTINGS_SCHEMA.items():
        if key not in incoming:
            continue
        try:
            clean[key] = check(incoming[key])
        except ValueError as e:
            errors.append(f"{key}: {e}")
    return clean, errors


def _read_alerts_from_redis(redis_client, count=200):
    """Reads the most recent real alerts from the 'ids:alerts' stream, newest first."""
    if not redis_client:
        return []
    try:
        raw = redis_client.xrevrange('ids:alerts', count=count)
        alerts = []
        for _msg_id, fields in raw:
            try:
                alerts.append(json.loads(fields['data']))
            except (KeyError, json.JSONDecodeError):
                continue
        return alerts
    except Exception as e:
        logger.warning(f"Redis read failed: {e}")
        return []


def _load_settings(redis_client, strict: bool = False) -> dict:
    """
    Defaults overlaid with whatever valid values are stored in Redis. Stored values go through
    the same schema as incoming ones, so a bad or stale value falls back to its default instead
    of breaking comparisons later.

    strict=False (display paths): Redis/JSON errors are logged and defaults are returned.
    strict=True (write paths): errors are raised, so a caller never persists defaults over the
    user's real settings just because one read failed.
    """
    settings = dict(DEFAULT_SETTINGS)
    if not redis_client:
        return settings
    try:
        stored = redis_client.get('ids:settings')
        saved = json.loads(stored) if stored else {}
    except Exception as e:
        if strict:
            raise
        logger.warning(f"Could not read settings from Redis: {e}")
        return settings
    if isinstance(saved, dict):
        clean, errors = validate_settings(saved)
        if errors:
            logger.warning(f"Ignoring invalid stored settings: {errors}")
        settings.update(clean)
    return settings


def migrate_legacy_settings(redis_client) -> bool:
    """Atomically strip a plaintext abuseIPDBKey from ids:settings.
    Returns True if a key was removed. Raises on Redis errors so callers can retry."""
    def _tx(pipe):
        stored = pipe.get('ids:settings')
        legacy = json.loads(stored) if stored else {}
        if not (isinstance(legacy, dict) and 'abuseIPDBKey' in legacy):
            return False
        legacy.pop('abuseIPDBKey')
        pipe.multi()
        pipe.set('ids:settings', json.dumps(legacy))
        return True
    return redis_client.transaction(_tx, 'ids:settings', value_from_callable=True)


def migrate_legacy_settings_until_done(redis_client, sleep=_sleep, interval=30.0) -> None:
    """Background task: retry transient Redis failures until the migration runs once.
    Non-transient errors (e.g. corrupt JSON in ids:settings) are logged once and abandoned --
    retrying them would loop forever. Never blocks startup."""
    while True:
        try:
            if migrate_legacy_settings(redis_client):
                logger.warning("Removed a legacy AbuseIPDB key from Redis settings; configure it in backend/.env.")
            return
        except _TRANSIENT_ERRORS as e:
            logger.warning(f"Legacy AbuseIPDB cleanup pending (Redis unavailable: {e}); retrying in {interval:.0f}s")
            sleep(interval)
        except Exception as e:
            logger.error(f"Legacy AbuseIPDB cleanup abandoned: ids:settings is unreadable ({e}). "
                         "Inspect or delete the key manually.")
            return


def register_routes(app, redis_client=None):
    """
    Registers JSON API routes consumed by the React dashboard.

    Every route here reads real data: the Redis 'ids:alerts' stream (written
    by RealTimeIDSPipeline once packet capture is running), the real
    AbuseIPDB API, the real on-disk GeoIP/model status, and real OS-level
    network introspection. There is no mock/demo data path.

    Performs no Redis I/O itself: registration runs at import time in main.py.
    """

    def _redis_up() -> bool:
        # The client is lazy and always truthy; only a round-trip proves Redis is reachable.
        try:
            return bool(redis_client and redis_client.ping())
        except Exception:
            return False

    # ---------------- Guard for every /api/ request ----------------

    @app.before_request
    def _guard_api():
        """
        1. Every /api/ request must name an allowed Host (DNS-rebinding defence; covers GETs too,
           since a rebound page could otherwise read alerts and the ARP table).
        2. POST/PUT/PATCH/DELETE can wipe the alert log, change severity thresholds and switch
           automatic firewall blocking on, so additionally:
           a. Browser requests must come from this app's own origin (or IDS_ALLOWED_ORIGINS).
              Matching Origin against Host is safe only because Host was validated in step 1.
           b. If IDS_API_TOKEN is set, they need `Authorization: Bearer <token>`.
        This guard covers Flask's HTTP routes only; the Socket.IO connection is authenticated
        separately in main.py (socket_authorized), using the same IDS_API_TOKEN.
        """
        if not request.path.startswith("/api/"):
            return None
        hostname = _request_hostname()
        if not hostname or hostname.lower() not in allowed_hosts():
            return jsonify({"status": "error", "message": "Host not allowed"}), 403
        # The token guards READS too (alerts, the LAN's ARP table, threat intel): the Host
        # check alone stops browsers, not scripts, which can send any Host header. The Socket.IO
        # channel already required it for the same alert data. /api/health stays open for
        # container healthchecks; it exposes only CPU/RAM/disk and Redis up/down.
        token = os.environ.get("IDS_API_TOKEN")
        if token and request.path != "/api/health":
            supplied = request.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
                return jsonify({"status": "error", "message": "Missing or invalid API token"}), 401
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        origin = request.headers.get("Origin")
        if origin:
            o = origin.rstrip("/")
            if urlparse(o).netloc != request.host and o not in allowed_origins():
                return jsonify({"status": "error", "message": "Origin not allowed"}), 403
        return None

    # ---------------- System health (real psutil metrics) ----------------

    @app.route('/api/health', methods=['GET'])
    def health_check():
        redis_ok = _redis_up()
        body = {
            'status': 'running' if redis_ok else 'degraded',
            # interval=None is non-blocking: compares against the previous call (0.0 on the first).
            'cpu': psutil.cpu_percent(interval=None),
            'ram': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('/').percent,
            'redis': 'connected' if redis_ok else 'disconnected',
        }
        return jsonify(body), (200 if redis_ok else 503)

    # ---------------- Alerts ----------------

    @app.route('/api/history', methods=['GET'])
    def get_history():
        alerts = _read_alerts_from_redis(redis_client)
        for a in alerts:
            a.setdefault('location', get_ip_location(a.get('src_ip')))
        return jsonify(alerts)

    @app.route('/api/history', methods=['DELETE'])
    def clear_history():
        """Backs the 'Clear Logs' button -- deletes the real Redis alert stream."""
        if not redis_client:
            return jsonify({'status': 'error', 'message': 'Redis unavailable'}), 503
        try:
            redis_client.delete('ids:alerts')
            return jsonify({'status': 'success', 'message': 'Alert history cleared'})
        except Exception as e:
            logger.error(f"Failed to clear history: {e}")
            return jsonify({'status': 'error', 'message': 'Failed to clear history'}), 500

    # ---------------- Threat Intelligence (real AbuseIPDB) ----------------

    @app.route('/api/threat-intel', methods=['GET'])
    def get_threat_intel():
        alerts = _read_alerts_from_redis(redis_client)

        # Aggregate local detection stats per source IP first (cheap, no API calls)
        by_ip = defaultdict(lambda: {'hits': 0, 'last_seen': 0, 'severity': 'MEDIUM'})
        severity_rank = {'MEDIUM': 0, 'HIGH': 1, 'CRITICAL': 2}
        for a in alerts:
            ip = a.get('src_ip')
            if not ip:
                continue
            bucket = by_ip[ip]
            bucket['hits'] += 1
            bucket['last_seen'] = max(bucket['last_seen'], a.get('timestamp', 0))
            sev = a.get('severity', 'MEDIUM')
            if severity_rank.get(sev, 0) > severity_rank.get(bucket['severity'], 0):
                bucket['severity'] = sev

        # Most active IPs first, capped -- each uncached IP costs one real AbuseIPDB call
        ranked_ips = sorted(by_ip.keys(), key=lambda ip: by_ip[ip]['hits'], reverse=True)
        abuse_results = {r['ip']: r for r in threat_intel_service.lookup_many(ranked_ips, redis_client)}

        records = []
        for ip in ranked_ips:
            local = by_ip[ip]
            abuse = abuse_results.get(ip, {"status": "not_configured"})
            records.append({
                'ip': ip,
                'source': 'Local Detection',
                'hits': local['hits'],
                'severity': local['severity'],
                'last_seen': local['last_seen'],
                'location': get_ip_location(ip),
                'abuse_score': abuse.get('abuse_score'),
                'reports': abuse.get('reports'),
                'isp': abuse.get('isp'),
                'last_reported': abuse.get('last_reported'),
                'intel_status': abuse.get('status'),
            })

        return jsonify({
            'records': records,
            'count': len(records),
            'geolocation_db': geo_utils.get_status(),
        })

    # ---------------- System status / model status ----------------

    @app.route('/api/system-info', methods=['GET'])
    def get_system_info():
        return jsonify(get_full_status(redis_client))

    @app.route('/api/reload-geoip', methods=['POST'])
    def reload_geoip():
        status = reload_reader()
        return jsonify(status)

    # ---------------- Network introspection ----------------

    @app.route('/api/network-interfaces', methods=['GET'])
    def get_network_interfaces():
        return jsonify(list_interfaces())

    @app.route('/api/network-devices', methods=['GET'])
    def get_network_devices():
        return jsonify(list_arp_devices())

    # ---------------- Settings ----------------

    @app.route('/api/settings', methods=['GET'])
    def get_settings():
        settings = _load_settings(redis_client)
        # Never echo the raw API key; only report whether one is configured in the environment
        settings['abuseIPDBKeySet'] = bool(os.environ.get('ABUSEIPDB_API_KEY'))
        settings.pop('abuseIPDBKey', None)
        return jsonify(settings)

    @app.route('/api/save-settings', methods=['POST'])
    def save_settings():
        incoming = request.get_json(silent=True)
        if not isinstance(incoming, dict):
            return jsonify({'status': 'error', 'message': 'Expected a JSON object'}), 400

        clean, errors = validate_settings(incoming)
        try:
            current = _load_settings(redis_client, strict=True)
        except Exception as e:
            # Never merge into defaults and write them back: that silently wipes saved settings.
            logger.error(f"Could not read current settings before save: {e}")
            return jsonify({'status': 'error', 'message': 'Redis unavailable -- settings not saved'}), 503
        current.update(clean)
        if current['highThreshold'] >= current['criticalThreshold']:
            errors.append("highThreshold: must be lower than criticalThreshold")
        if errors:
            return jsonify({'status': 'error', 'message': 'Invalid settings', 'errors': errors}), 400
        if redis_client:
            try:
                redis_client.set('ids:settings', json.dumps(current))
            except Exception as e:
                logger.error(f"Failed to persist settings: {e}")
                return jsonify({'status': 'error', 'message': 'Failed to persist settings'}), 500
        else:
            return jsonify({'status': 'error', 'message': 'Redis unavailable -- settings not persisted'}), 503

        return jsonify({'status': 'success', 'message': 'Configuration updated'})