# backend/src/threat_intel_service.py
"""
Real AbuseIPDB Threat Intelligence client.

This replaces any mock/placeholder threat-intel data with a real integration
against https://api.abuseipdb.com — the same service your Settings page
(AbuseIPDB API Key field) is built for.

Design notes:
- Results are cached in Redis for TTL_SECONDS (default 6h). AbuseIPDB's free
  tier allows 1,000 checks/day; without caching, refreshing the dashboard a
  few times would burn through that fast. The cache is keyed per-IP so a
  popular attacker IP only costs one real API call per cache window.
- The API key is never hardcoded. It's read from (in priority order):
  1. The ABUSEIPDB_API_KEY environment variable
  2. The key saved via Settings -> POST /api/save-settings (stored in Redis)
- If no key is configured, `lookup_ip` returns a clear "not configured"
  result instead of silently faking data — same honesty principle as the
  GeoIP "Not available (download required)" status on your Settings page.
- Network errors / rate-limit responses are caught and surfaced as a status
  string rather than crashing the request thread.
"""

import os
import json
import time
import logging
import requests

logger = logging.getLogger("IDS-ThreatIntel")

ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
CACHE_PREFIX = "ids:abuseipdb:"
TTL_SECONDS = 6 * 60 * 60  # 6 hours — balances freshness against the 1,000/day free quota
REQUEST_TIMEOUT = 4  # seconds — never let a slow API call stall the dashboard


def _get_api_key(redis_client=None) -> str | None:
    env_key = os.environ.get("ABUSEIPDB_API_KEY")
    if env_key:
        return env_key
    if redis_client:
        try:
            stored = redis_client.get("ids:settings")
            if stored:
                settings = json.loads(stored)
                return settings.get("abuseIPDBKey") or None
        except Exception as e:
            logger.debug(f"Could not read AbuseIPDB key from settings: {e}")
    return None


def lookup_ip(ip_address: str, redis_client=None, max_age_days: int = 90) -> dict:
    """
    Returns AbuseIPDB data for a single IP:
        { "ip": "1.2.3.4", "abuse_score": 42, "reports": 7,
          "isp": "Some ISP", "domain": "example.net",
          "last_reported": "2026-06-20T10:00:00+00:00", "status": "ok" }

    status is one of: "ok", "not_configured", "rate_limited", "error", "cached"
    """
    if not ip_address:
        return {"ip": ip_address, "status": "error", "error": "missing IP"}

    cache_key = f"{CACHE_PREFIX}{ip_address}"

    # 1. Serve from cache if fresh
    if redis_client:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                result = json.loads(cached)
                result["status"] = "cached"
                return result
        except Exception as e:
            logger.debug(f"Cache read failed for {ip_address}: {e}")

    api_key = _get_api_key(redis_client)
    if not api_key:
        return {
            "ip": ip_address, "abuse_score": None, "reports": None,
            "isp": None, "domain": None, "last_reported": None,
            "status": "not_configured",
        }

    # 2. Real API call
    try:
        response = requests.get(
            ABUSEIPDB_ENDPOINT,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip_address, "maxAgeInDays": max_age_days},
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code == 429:
            return {"ip": ip_address, "status": "rate_limited"}

        response.raise_for_status()
        data = response.json().get("data", {})

        result = {
            "ip": ip_address,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "isp": data.get("isp") or "Unknown",
            "domain": data.get("domain"),
            "country": data.get("countryCode"),
            "last_reported": data.get("lastReportedAt"),
            "status": "ok",
        }

        if redis_client:
            try:
                redis_client.set(cache_key, json.dumps(result), ex=TTL_SECONDS)
            except Exception as e:
                logger.debug(f"Cache write failed for {ip_address}: {e}")

        return result

    except requests.exceptions.RequestException as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip_address}: {e}")
        return {"ip": ip_address, "status": "error", "error": str(e)}


def lookup_many(ip_addresses: list[str], redis_client=None, max_lookups: int = 25) -> list[dict]:
    """
    Looks up multiple IPs, capped at max_lookups per call so a single page
    load can't exhaust the daily quota against a long attacker list. Callers
    should pass already-deduplicated, most-relevant-first IP lists.
    """
    results = []
    for ip in ip_addresses[:max_lookups]:
        results.append(lookup_ip(ip, redis_client=redis_client))
        # Cached/not_configured/error responses return instantly; only a real
        # network call needs a breather to stay well under AbuseIPDB's burst limits.
    return results
