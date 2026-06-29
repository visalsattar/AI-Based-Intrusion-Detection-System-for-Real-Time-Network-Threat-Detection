# backend/routes.py
import json
import logging
from collections import defaultdict
from flask import jsonify, request
import psutil

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
    "abuseIPDBKey": "b53a79c38b09ffa49c72005954d5b6f59e31a40876d62fed29eff5e94fd5efd33e03806e01b7d8ef",
    "criticalThreshold": 0.95,
    "highThreshold": 0.85,
}


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


def _load_settings(redis_client) -> dict:
    settings = dict(DEFAULT_SETTINGS)
    if redis_client:
        try:
            stored = redis_client.get('ids:settings')
            if stored:
                settings.update(json.loads(stored))
        except Exception as e:
            logger.warning(f"Could not read settings from Redis: {e}")
    return settings


def register_routes(app, redis_client=None):
    """
    Registers JSON API routes consumed by the React dashboard.

    Every route here reads real data: the Redis 'ids:alerts' stream (written
    by RealTimeIDSPipeline once packet capture is running), the real
    AbuseIPDB API, the real on-disk GeoIP/model status, and real OS-level
    network introspection. There is no mock/demo data path.
    """

    # ---------------- System health (real psutil metrics) ----------------

    @app.route('/api/health', methods=['GET'])
    def health_check():
        return jsonify({
            'status': 'running',
            'cpu': psutil.cpu_percent(interval=0.1),
            'ram': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('/').percent,
            'redis': 'connected' if redis_client else 'disconnected',
        })

    # ---------------- Alerts ----------------

    @app.route('/api/history', methods=['GET'])
    def get_history():
        alerts = _read_alerts_from_redis(redis_client)
        for a in alerts:
            a.setdefault('location', get_ip_location(a.get('src_ip')))
        return jsonify(alerts)

    @app.route('/api/history', methods=['DELETE'])
    def clear_history():
        """Backs the 'Clear Logs' button — actually trims the real Redis stream."""
        if not redis_client:
            return jsonify({'status': 'error', 'message': 'Redis unavailable'}), 503
        try:
            redis_client.delete('ids:alerts')
            return jsonify({'status': 'success', 'message': 'Alert history cleared'})
        except Exception as e:
            logger.error(f"Failed to clear history: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

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

        # Most active IPs first, capped — each uncached IP costs one real AbuseIPDB call
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
        # Never echo the raw API key back to the client beyond a masked preview
        if settings.get('abuseIPDBKey'):
            settings['abuseIPDBKeySet'] = True
            settings['abuseIPDBKey'] = ''
        else:
            settings['abuseIPDBKeySet'] = False
        return jsonify(settings)

    @app.route('/api/save-settings', methods=['POST'])
    def save_settings():
        incoming = request.json or {}
        current = _load_settings(redis_client)

        # Don't overwrite a previously-saved key with a blank field submission
        if not incoming.get('abuseIPDBKey'):
            incoming.pop('abuseIPDBKey', None)

        current.update(incoming)
        if redis_client:
            try:
                redis_client.set('ids:settings', json.dumps(current))
            except Exception as e:
                logger.error(f"Failed to persist settings: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500
        else:
            return jsonify({'status': 'error', 'message': 'Redis unavailable — settings not persisted'}), 503

        return jsonify({'status': 'success', 'message': 'Configuration updated'})
