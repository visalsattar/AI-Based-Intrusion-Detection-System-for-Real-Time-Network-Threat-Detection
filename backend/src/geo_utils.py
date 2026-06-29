# backend/src/geo_utils.py
"""
GeoIP resolution utility.

Wraps the local MaxMind GeoLite2-City database (backend/config/GeoLite2-City.mmdb)
so any module — the real-time IDS pipeline, the mock alert generator, or the
REST API — can turn a source IP into a human-readable location + lat/lon pair
for map rendering on the Threat Intel page.

Falls back gracefully if the database is missing or the IP can't be resolved
(this is expected for private/RFC1918 addresses), so it never crashes the
alert pipeline.
"""

import os
import logging
import geoip2.database
import geoip2.errors

logger = logging.getLogger("IDS-GeoUtils")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GEOIP_DB_PATH = os.path.join(_BASE_DIR, "..", "config", "GeoLite2-City.mmdb")

_reader = None
_reader_failed = False


def _get_reader():
    """Lazily opens the mmdb reader once and reuses it (it's thread-safe for reads)."""
    global _reader, _reader_failed
    if _reader is not None or _reader_failed:
        return _reader
    try:
        if os.path.exists(GEOIP_DB_PATH):
            _reader = geoip2.database.Reader(GEOIP_DB_PATH)
            logger.info(f"GeoIP database loaded from {GEOIP_DB_PATH}")
        else:
            logger.warning(f"GeoIP database not found at {GEOIP_DB_PATH}")
            _reader_failed = True
    except Exception as e:
        logger.error(f"Failed to open GeoIP database: {e}")
        _reader_failed = True
    return _reader


def is_private_ip(ip_address: str) -> bool:
    """Quick check for RFC1918 / loopback ranges that GeoIP can't resolve anyway."""
    if not ip_address:
        return True
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.2", "172.3", "192.168.", "127.")
    return ip_address in ("localhost",) or ip_address.startswith(private_prefixes)


def reload_reader():
    """
    Forces the GeoIP reader to reopen the mmdb file on the next lookup.
    Used by the Settings page's 'Reload Database' action after you've just
    downloaded/placed GeoLite2-City.mmdb without restarting the container.
    """
    global _reader, _reader_failed
    if _reader is not None:
        try:
            _reader.close()
        except Exception:
            pass
    _reader = None
    _reader_failed = False
    return get_status()


def get_status() -> dict:
    """Real on-disk status of the GeoIP database, for System Information / Settings."""
    exists = os.path.exists(GEOIP_DB_PATH)
    if not exists:
        return {"available": False, "path": GEOIP_DB_PATH, "message": "Not available (download required)"}
    reader = _get_reader()
    if reader is None:
        return {"available": False, "path": GEOIP_DB_PATH, "message": "File present but failed to load"}
    size_mb = round(os.path.getsize(GEOIP_DB_PATH) / (1024 * 1024), 1)
    return {"available": True, "path": GEOIP_DB_PATH, "message": f"Loaded ({size_mb} MB)"}


def get_ip_location(ip_address: str) -> dict:
    """
    Resolves an IP to a location dict consumable directly by the frontend map:
        { "label": "Frankfurt, Germany", "city": "Frankfurt", "country": "Germany",
          "lat": 50.1109, "lon": 8.6821 }

    Returns a safe fallback dict (no lat/lon) instead of raising on any failure.
    """
    fallback = {"label": "Unknown Location", "city": None, "country": None,
                "lat": None, "lon": None}

    if not ip_address:
        return fallback

    if is_private_ip(ip_address):
        return {"label": "Internal Network", "city": "Internal", "country": "LAN",
                "lat": None, "lon": None}

    reader = _get_reader()
    if reader is None:
        return fallback

    try:
        response = reader.city(ip_address)
        city = response.city.name or "Unknown City"
        country = response.country.name or "Unknown Country"
        return {
            "label": f"{city}, {country}",
            "city": city,
            "country": country,
            "lat": response.location.latitude,
            "lon": response.location.longitude,
        }
    except geoip2.errors.AddressNotFoundError:
        return fallback
    except Exception as e:
        logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
        return fallback
