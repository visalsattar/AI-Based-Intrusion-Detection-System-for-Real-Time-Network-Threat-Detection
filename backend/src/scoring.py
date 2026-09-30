"""
Pure scoring/settings helpers shared by ids_pipeline.py and calibrate_override.py.

No scapy / tensorflow / flask imports, so this module is cheap to import in tests
and in offline tools. Keep live and offline math here so they cannot drift apart.
"""
import logging
import math

logger = logging.getLogger(__name__)

# Lowest alert cutoff any sensitivity level can produce (ids_pipeline: "high" ->
# max(0.50, alert_threshold - 0.15)). An override below this can never raise an
# alert on its own; it would only relabel detection_source.
OVERRIDE_FLOOR = 0.50

SETTINGS_DEFAULTS = {
    "sensitivity": "medium",
    "autoBlock": False,
    "criticalThreshold": 0.95,
    "highThreshold": 0.85,
}

_THRESHOLD_BOUNDS = {
    # Must match routes.SETTINGS_SCHEMA.
    "criticalThreshold": (0.80, 0.999),
    "highThreshold": (0.50, 0.95),
}


def attack_probability(proba, classes):
    """
    P(attack) per row = 1 - P(benign class 0).

    Correct for both binary ([0, 1]) and multi-class RFs. The previous
    `proba[:, classes.index(1)]` returned P(class 1) only, which in a multi-class
    model is ONE attack type -- every other attack type scored ~0.
    """
    classes = list(classes)
    if 0 not in classes:
        raise ValueError(f"classifier has no benign class 0 (classes={classes})")
    return 1.0 - proba[:, classes.index(0)]


def clamp_override(value, floor: float = OVERRIDE_FLOOR) -> float:
    """
    Validate a calibrated override threshold. Non-finite or >1 values raise
    ValueError (caller falls back to coded defaults). Values below `floor` are
    raised to it, loudly, because they cannot trigger an alert by themselves.
    """
    v = float(value)
    if not math.isfinite(v) or v > 1.0:
        raise ValueError(f"override threshold must be finite and <= 1.0, got {value!r}")
    if v < floor:
        logger.warning(
            f"Calibrated override {v:.4f} is below the minimum alert cutoff "
            f"{floor:.2f}; clamping. It could never raise an alert on its own."
        )
        return floor
    return v


def sanitize_settings(raw) -> dict:
    """
    Defensive copy of the settings document read from Redis. The HTTP route
    validates on write, but anything with Redis write access bypasses the route,
    and one bad type (e.g. a string threshold) used to crash a whole scoring batch.
    Invalid fields fall back to defaults; they never raise.
    """
    s = dict(SETTINGS_DEFAULTS)
    if not isinstance(raw, dict):
        return s

    if raw.get("sensitivity") in ("low", "medium", "high"):
        s["sensitivity"] = raw["sensitivity"]

    for key, (lo, hi) in _THRESHOLD_BOUNDS.items():
        v = raw.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and lo <= v <= hi:
            s[key] = float(v)

    if s["highThreshold"] >= s["criticalThreshold"]:
        s["criticalThreshold"] = SETTINGS_DEFAULTS["criticalThreshold"]
        s["highThreshold"] = SETTINGS_DEFAULTS["highThreshold"]

    # Destructive action: only an explicit JSON true enables it. "true", 1, etc. do not.
    s["autoBlock"] = raw.get("autoBlock") is True
    return s