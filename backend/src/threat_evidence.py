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


def _bar(draw, x, y, w, h, value, color):
    """Horizontal score bar, 0..1. Unknown value -> empty track only."""
    draw.rounded_rectangle((x, y, x + w, y + h), h // 2, fill="#232b38")
    if isinstance(value, (int, float)):
        filled = max(0.0, min(1.0, float(value)))
        if filled > 0:
            draw.rounded_rectangle((x, y, x + max(h, int(w * filled)), y + h),
                                   h // 2, fill=color)


def _draw_card(alert, evidence_id, image_path):
    image = Image.new("RGB", (_WIDTH, _HEIGHT), _BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((28, 28, _WIDTH - 28, _HEIGHT - 28), 24, fill=_PANEL)

    title_font = _font(36, bold=True)
    head_font = _font(15, bold=True)
    body_font = _font(20)
    mono_font = _font(20, bold=True)
    label_font = _font(13, bold=True)
    small_font = _font(13)

    severity = str(alert.get("severity") or "UNKNOWN").upper()
    severity_color = _SEVERITY.get(severity, "#cbd5e1")

    # severity accent stripe down the left edge
    draw.rounded_rectangle((28, 28, 40, _HEIGHT - 28), 6, fill=severity_color)

    draw.text((72, 58), "AI-IDS  /  THREAT EVIDENCE", fill=_ACCENT, font=head_font)
    draw.text((72, 86), "Detected network anomaly", fill=_TEXT, font=title_font)

    bbox = draw.textbbox((0, 0), severity, font=head_font)
    badge_w = bbox[2] - bbox[0] + 34
    draw.rounded_rectangle((_WIDTH - 72 - badge_w, 60, _WIDTH - 72, 96),
                           12, fill=severity_color)
    draw.text((_WIDTH - 72 - badge_w + 17, 70), severity, fill=_BG, font=head_font)

    try:
        timestamp_text = datetime.fromtimestamp(
            float(alert.get("timestamp")), timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        timestamp_text = "unknown time"

    draw.line((72, 140, _WIDTH - 72, 140), fill="#2b3444", width=1)

    # ---- scores block (left column) -------------------------------------
    draw.text((72, 160), "MODEL SCORES", fill=_MUTED, font=label_font)
    scores = [
        ("Fused anomaly score", alert.get("anomaly_score"), severity_color),
        ("Autoencoder (unsupervised)", alert.get("ae_anomaly_score"), "#38bdf8"),
        ("Random forest (supervised)", alert.get("rf_attack_prob"), "#4ade80"),
    ]
    y = 190
    for label, value, color in scores:
        draw.text((72, y), label, fill=_TEXT, font=body_font)
        draw.text((72, y + 28), _score(value), fill=_MUTED, font=small_font)
        _bar(draw, 400, y + 6, 150, 14, value, color)
        y += 66

    # ---- flow block (right column) --------------------------------------
    draw.text((620, 160), "FLOW", fill=_MUTED, font=label_font)
    flow_rows = [
        ("Source", alert.get("src_ip", "Unknown")),
        ("Destination", f"{alert.get('dst_ip', 'Unknown')}  ({alert.get('protocol', '?')})"),
        ("Packets / bytes",
         f"{alert.get('packet_count', 'n/a')} / {alert.get('bytes_transferred', 'n/a')}"),
    ]
    y = 190
    for label, value in flow_rows:
        draw.text((620, y), label, fill=_MUTED, font=small_font)
        draw.text((620, y + 18), str(value)[:40], fill=_TEXT, font=mono_font)
        y += 66

    draw.line((72, 400, _WIDTH - 72, 400), fill="#2b3444", width=1)

    # ---- detail rows -----------------------------------------------------
    coverage = alert.get("feature_coverage")
    coverage_text = (f"{float(coverage) * 100:.0f}% of the 78 trained features"
                     if isinstance(coverage, (int, float)) else "not recorded")
    details = [
        ("Timestamp", timestamp_text),
        ("Threat type", alert.get("threat_type", "Unknown")),
        ("Detection source", alert.get("detection_source", "Unknown")),
        ("Live feature coverage", coverage_text),
        ("Evidence origin", alert.get("evidence_origin", "live_unclassified")),
    ]
    y = 420
    for label, value in details:
        value = str(value).replace("\r", " ").replace("\n", " ")[:90]
        draw.text((72, y), label.upper(), fill=_MUTED, font=label_font)
        draw.text((330, y - 3), value, fill=_TEXT, font=body_font)
        y += 38

    # ---- footer ----------------------------------------------------------
    draw.line((72, 618, _WIDTH - 72, 618), fill="#303949", width=1)
    draw.text((72, 634), f"Evidence ID: {evidence_id}", fill=_ACCENT, font=small_font)
    provenance = str(alert.get("evidence_origin", "live_unclassified"))
    if provenance == "synthetic_fusion_verification":
        note = "SYNTHETIC TEST EVIDENCE - constructed packets, not captured traffic."
        note_color = _SEVERITY["HIGH"]
    elif provenance == "live_lab":
        note = "Controlled live-lab capture. Alert metadata only; no packet payloads stored."
        note_color = _MUTED
    else:
        note = "Live capture, unclassified environment. Alert metadata only; no payloads stored."
        note_color = _MUTED
    draw.text((72, 658), note, fill=note_color, font=small_font)
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