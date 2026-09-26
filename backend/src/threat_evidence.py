"""Persist a thesis-friendly JSON record and PNG evidence card per IDS alert."""
import json
import os
import tempfile
import threading
import uuid
from datetime import datetime, timezone

from PIL import Image, ImageDraw, ImageFont

_WRITE_LOCK = threading.Lock()
_WIDTH, _HEIGHT = 1200, 720
_BG = "#0b0e14"
_PANEL = "#151b25"
_TEXT = "#e8eaed"
_MUTED = "#9aa4b5"
_ACCENT = "#4ade80"
_SEVERITY = {
    "CRITICAL": "#fb7185",
    "HIGH": "#fbbf24",
    "MEDIUM": "#38bdf8",
    "LOW": "#4ade80",
}

# Evidence must say where it came from.  In particular, a constructed flow
# passed through verify_ensemble.py is valuable test evidence, but it is not a
# live observation and must never be presented as one.
_EVIDENCE_ORIGINS = {
    "synthetic_fusion_verification",
    "live_lab",
    "live_unclassified",
}


def evidence_origin():
    """Return a safe, explicit provenance label for a saved evidence item."""
    origin = os.environ.get("IDS_EVIDENCE_ORIGIN", "live_unclassified").strip().lower()
    if origin not in _EVIDENCE_ORIGINS:
        return "live_unclassified"
    return origin


def normalise_evidence_origin(origin):
    origin = str(origin or "").strip().lower()
    return origin if origin in _EVIDENCE_ORIGINS else "live_unclassified"


def _font(size, bold=False):
    candidates = (
        ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
         "C:/Windows/Fonts/arialbd.ttf"]
        if bold else
        ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
         "C:/Windows/Fonts/arial.ttf"]
    )
    for name in candidates:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _score(value):
    if isinstance(value, (int, float)):
        return f"{value:.4f} ({value * 100:.1f}%)"
    return "not available"


def _draw_card(alert, evidence_id, image_path):
    image = Image.new("RGB", (_WIDTH, _HEIGHT), _BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((32, 32, _WIDTH - 32, _HEIGHT - 32), 22, fill=_PANEL)

    title_font = _font(34, bold=True)
    body_font = _font(21)
    label_font = _font(16, bold=True)
    small_font = _font(14)

    draw.text((68, 62), "AI-IDS  /  THREAT EVIDENCE", fill=_ACCENT, font=label_font)
    draw.text((68, 95), "Detected network anomaly", fill=_TEXT, font=title_font)

    severity = str(alert.get("severity") or "UNKNOWN").upper()
    severity_color = _SEVERITY.get(severity, "#cbd5e1")
    bbox = draw.textbbox((0, 0), severity, font=label_font)
    badge_width = bbox[2] - bbox[0] + 36
    draw.rounded_rectangle((_WIDTH - 68 - badge_width, 67, _WIDTH - 68, 103),
                           12, fill=severity_color)
    draw.text((_WIDTH - 50 - (bbox[2] - bbox[0]), 76),
              severity, fill=_BG, font=label_font)

    try:
        timestamp_text = datetime.fromtimestamp(
            float(alert.get("timestamp")), timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        timestamp_text = "unknown time"

    fields = [
        ("Evidence origin", alert.get("evidence_origin", "live_unclassified")),
        ("Timestamp", timestamp_text),
        ("Threat type", alert.get("threat_type", "Unknown")),
        ("Source IP", alert.get("src_ip", "Unknown")),
        ("Destination IP", alert.get("dst_ip", "Unknown")),
        ("Protocol", alert.get("protocol", "Unknown")),
        ("Anomaly score", _score(alert.get("anomaly_score"))),
        ("Autoencoder score", _score(alert.get("ae_anomaly_score"))),
        ("Random forest score", _score(alert.get("rf_attack_prob"))),
        ("Packets / bytes", f"{alert.get('packet_count', 'n/a')} / {alert.get('bytes_transferred', 'n/a')}"),
        ("Detection source", alert.get("detection_source", "Unknown")),
    ]

    y = 158
    for label, value in fields:
        value = str(value).replace("\r", " ").replace("\n", " ")[:120]
        draw.text((72, y), label.upper(), fill=_MUTED, font=label_font)
        draw.text((365, y - 2), value, fill=_TEXT, font=body_font)
        y += 43

    draw.line((68, 612, _WIDTH - 68, 612), fill="#303949", width=1)
    draw.text((72, 630), f"Evidence ID: {evidence_id}", fill=_ACCENT, font=small_font)
    provenance = str(alert.get("evidence_origin", "live_unclassified"))
    note = ("SYNTHETIC TEST EVIDENCE — not live captured traffic."
            if provenance == "synthetic_fusion_verification"
            else "Alert metadata only. No packet payloads are included.")
    draw.text((72, 654), note,
              fill=_MUTED, font=small_font)
    image.save(image_path, format="PNG", optimize=True)


def save_threat_evidence(alert):
    """Write an append-only JSONL record and a PNG summary image for an alert."""
    output_dir = os.environ.get("IDS_EVIDENCE_DIR") or os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "evidence")
    )
    os.makedirs(output_dir, exist_ok=True)

    now = datetime.now(timezone.utc)
    evidence_id = f"{now.strftime('%Y%m%dT%H%M%S_%fZ')}_{uuid.uuid4().hex[:8]}"
    image_name = f"threat-{evidence_id}.png"
    image_path = os.path.join(output_dir, image_name)
    record_path = os.path.join(output_dir, "alerts.jsonl")

    fields = {
        "evidence_id": evidence_id,
        "evidence_image": image_name,
        "evidence_origin": normalise_evidence_origin(alert.get("evidence_origin") or evidence_origin()),
    }
    record = dict(alert)
    record.update(fields)
    record["evidence_saved_at"] = now.isoformat()

    fd, temp_path = tempfile.mkstemp(prefix=".threat-", suffix=".png", dir=output_dir)
    os.close(fd)
    try:
        _draw_card(record, evidence_id, temp_path)
        os.replace(temp_path, image_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
    with _WRITE_LOCK:
        with open(record_path, "a", encoding="utf-8") as records:
            records.write(line + "\n")
    return fields
