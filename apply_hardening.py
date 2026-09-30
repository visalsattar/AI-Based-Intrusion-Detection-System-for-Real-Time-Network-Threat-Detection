"""
Applies the IDS hardening fixes in one step.

Run from the repository root:
    python apply_hardening.py

What it does:
  1. Writes backend/src/scoring.py
  2. Patches backend/src/ids_pipeline.py      (backup: ids_pipeline.py.bak)
  3. Patches backend/src/calibrate_override.py (backup: calibrate_override.py.bak)

All-or-nothing: every edit is located first. If any anchor text is missing or
ambiguous, NOTHING is written and the script says which edit failed.
Line endings (CRLF/LF) are preserved.
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "backend" / "src"
PIPELINE = SRC / "ids_pipeline.py"
CALIBRATE = SRC / "calibrate_override.py"
SCORING = SRC / "scoring.py"


class PatchError(Exception):
    pass


def sub_once(text, old, new, label):
    n = text.count(old)
    if n != 1:
        raise PatchError(f"[{label}] anchor found {n} times (expected 1)")
    return text.replace(old, new, 1)


def replace_between(text, start, end, new, label):
    """Replace text from `start` (inclusive) up to `end` (exclusive)."""
    if text.count(start) != 1:
        raise PatchError(f"[{label}] start anchor found {text.count(start)} times (expected 1)")
    i = text.index(start)
    j = text.find(end, i + len(start))
    if j == -1:
        raise PatchError(f"[{label}] end anchor not found after start")
    return text[:i] + new + text[j:]


def read_lf(path):
    raw = path.read_bytes().decode("utf-8")
    crlf = "\r\n" in raw
    return raw.replace("\r\n", "\n"), crlf


def write_eol(path, text, crlf):
    if crlf:
        text = text.replace("\n", "\r\n")
    path.write_bytes(text.encode("utf-8"))


# =============================================================== scoring.py

SCORING_SRC = r'''"""
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
'''

# =============================================================== ids_pipeline.py edits

INFERENCE_NEW = '''    def _inference_batch(self):
        """Score every finished flow once, then drop it. Caller must hold self._lock."""
        n_packets = len(self.packet_buffer)
        self.packet_buffer = []
        self._last_batch_at = time.time()
        finished = self._collect_finished_flows()

        if finished:
            logger.debug(f"AI scoring {len(finished)} finished flow(s) ({n_packets} new packets)")
        try:
            if finished:
                self._score_flows(finished)
        except Exception as e:
            logger.error(f"Inference batch error: {e}", exc_info=True)
        finally:
            # Scored flows are finished; never re-score them.
            for k in finished:
                self.flow_tracker.pop(k, None)
            try:
                # Hard cap: score the oldest overflow flows BEFORE dropping them, so a
                # high-cardinality flood cannot evict an attack flow unscored.
                self._evict_overflow()
            except Exception as e:
                logger.error(f"Overflow scoring failed: {e}", exc_info=True)
            self._expire_blocks()

    def _score_flows(self, keys):
        """Extract, scale, predict and dispatch alerts for `keys`. Caller holds self._lock."""
        features_batch = []
        flow_keys_batch = []

        for flow_key in keys:
            features = self._extract_flow_features(flow_key)
            if features is not None:
                features_batch.append(features)
                flow_keys_batch.append(flow_key)

        if not features_batch:
            return

        feature_names = list(
            getattr(
                self.feature_scaler,
                "feature_names_in_",
                [f"f{i}" for i in range(len(features_batch[0]))],
            )
        )

        if len(feature_names) != len(features_batch[0]):
            raise ValueError(
                f"Live feature count mismatch: expected {len(feature_names)}, "
                f"got {len(features_batch[0])}"
            )

        features_array = np.asarray(features_batch, dtype=np.float32)

        # The scaler was fitted with named CICFlowMeter columns. Passing a
        # DataFrame preserves the exact feature-name/order contract.
        features_df = pd.DataFrame(features_array, columns=feature_names)
        features_normalized = self.feature_scaler.transform(features_df)

        reconstructed = self.autoencoder.predict(
            features_normalized,
            batch_size=len(features_normalized),
            verbose=0
        )

        # Real anomaly signal: per-sample reconstruction error (MSE between the
        # scaled input and the autoencoder's reconstruction of it).
        sq = np.square(features_normalized - reconstructed)
        recon_errors = np.mean(sq, axis=1)

        if logger.isEnabledFor(logging.DEBUG):
            names = self.feature_scaler.feature_names_in_
            for i, k in enumerate(flow_keys_batch):
                top = np.argsort(sq[i])[-3:][::-1]
                logger.debug("TOPFEAT %s -> %s", k,
                             ", ".join(f"{names[j]}={features_normalized[i, j]:.1f}" for j in top))

        # Supervised cross-check. P(attack) = 1 - P(benign), correct for both the
        # binary and the multi-class RF (see scoring.attack_probability).
        rf_attack_probs = [None] * len(flow_keys_batch)
        threat_names = [None] * len(flow_keys_batch)
        if self.random_forest is not None:
            try:
                proba = self.random_forest.predict_proba(features_normalized)
                rf_attack_probs = attack_probability(proba, self.random_forest.classes_)
                if self._rf_multiclass:
                    preds = self.random_forest.predict(features_normalized)
                    threat_names = [
                        self._label_map.get(int(p), f"Class {p}") for p in preds
                    ]
            except Exception as e:
                logger.warning(f"Random Forest inference failed this batch ({e}); using autoencoder only")

        if self._dump_path:
            self._dump_features(flow_keys_batch, features_array, recon_errors, rf_attack_probs)

        failed = self._dispatch_predictions(flow_keys_batch, recon_errors,
                                            rf_attack_probs, threat_names)
        if failed:
            logger.error(f"{failed} flow(s) failed alert processing this batch")

    def _dispatch_predictions(self, keys, recon_errors, rf_probs, threat_names) -> int:
        """Per-flow isolation: one bad flow must not drop alerts for the rest of the batch."""
        failed = 0
        for k, e, p, n in zip(keys, recon_errors, rf_probs, threat_names):
            try:
                self._process_prediction(k, float(e), None if p is None else float(p), n)
            except Exception as ex:
                failed += 1
                logger.error(f"Alert processing failed for {k}: {ex}", exc_info=True)
        return failed

'''

EVICT_OVERFLOW_NEW = '''    def _evict_overflow(self) -> int:
        """
        Hard-cap enforcement that SCORES the oldest overflow flows before dropping
        them. The old hard cap deleted them unscored, so an attacker could flood the
        table with junk flows to push a real attack flow out undetected.
        Flows are always removed (finally), so the memory bound holds even if scoring fails.
        """
        overflow = len(self.flow_tracker) - self.max_tracked_flows
        if overflow <= 0:
            return 0
        oldest = [k for k, _ in heapq.nsmallest(
            overflow, self.flow_tracker.items(), key=lambda kv: kv[1]['last_seen'])]
        try:
            self._score_flows(oldest)
        finally:
            for k in oldest:
                self.flow_tracker.pop(k, None)
            self.evicted_flows_total += len(oldest)
            logger.warning(f"flow_tracker over cap: scored and evicted {len(oldest)} "
                           f"oldest flows (total {self.evicted_flows_total})")
        return len(oldest)

'''

FUSION_NEW = '''        ae_score = recon_error / (recon_error + self.recon_threshold)

        flow = self.flow_tracker[flow_key]
        # Use the stored flow initiator, NOT flow_key[0][0]: flow_key is
        # built with sorted([...]), so flow_key[0] is the lexicographically
        # smaller endpoint, not the real source.
        src_ip = flow['init_src']
        settings = self._load_settings()

        # Sensitivity changes the minimum anomaly score needed to emit an alert.
        # Severity thresholds still decide the label (MEDIUM/HIGH/CRITICAL).
        # Computed BEFORE fusion so an override is only labelled when it alerts.
        sensitivity_cutoffs = {
            "low": min(0.99, self.alert_threshold + 0.10),
            "medium": self.alert_threshold,
            "high": max(0.50, self.alert_threshold - 0.15),
        }
        alert_cutoff = sensitivity_cutoffs.get(
            settings.get("sensitivity", "medium"), self.alert_threshold
        )

        override_reason = None
        if rf_attack_prob is not None:
            fused_score = 0.5 * ae_score + 0.5 * rf_attack_prob
            anomaly_score = fused_score
            # RF first: a confident known-pattern match is the more specific label.
            if rf_attack_prob > self.RF_OVERRIDE_CONF:
                override_reason = 'random forest override (known attack pattern)'
                anomaly_score = max(fused_score, rf_attack_prob)
            elif ae_score > self.AE_OVERRIDE_CONF:
                override_reason = 'autoencoder override (possible novel attack)'
                anomaly_score = max(fused_score, ae_score)
            if override_reason and anomaly_score <= alert_cutoff:
                override_reason = None   # did not alert -> do not claim it did
        else:
            # AE-only mode: the autoencoder score IS the anomaly score.
            fused_score = ae_score
            anomaly_score = ae_score

'''

HANDSHAKE_NEW = '''        # Handshake verification for AutoBlock. A blind spoofer never receives our
        # SYN-ACK, so it cannot send a forward ACK acknowledging synack_seq + 1.
        if TCP in packet:
            tcp = packet[TCP]
            fl = int(tcp.flags)
            if (not is_forward and flow['init_syn'] and (fl & 0x12) == 0x12
                    and flow.get('synack_seq') is None):
                flow['synack_seq'] = int(tcp.seq)
            elif (is_forward and flow.get('synack_seq') is not None
                    and not flow.get('handshake_complete')
                    and (fl & 0x12) == 0x10
                    and int(tcp.ack) == (flow['synack_seq'] + 1) % 2**32):
                flow['handshake_complete'] = True

        flow['packet_list'].append((packet, is_forward))
'''

SHOULD_BLOCK_NEW = '''    def _should_block(self, flow) -> bool:
        """
        Permit AutoBlock only for an inbound TCP flow to one of this host's IPs whose
        initiator COMPLETED a handshake: bare SYN, our SYN-ACK, then a forward ACK
        acknowledging synack_seq + 1. A blind spoofer cannot produce that ACK, so a
        forged SYN claiming to be e.g. your DNS resolver can no longer get it blocked.

        Consequence: SYN floods are never auto-blocked (their sources are spoofable).
        Mitigate those with SYN cookies (net.ipv4.tcp_syncookies=1), not IP blocks.
        """
        src = flow['init_src']
        if src in self._whitelist or src in self._blocked:
            return False
        if len(self._blocked) >= self.MAX_ACTIVE_BLOCKS:
            logger.warning(f"[IPS] {len(self._blocked)} active blocks (cap); not blocking {src}")
            return False
        if (flow['protocol'] != 6 or not flow.get('init_syn')
                or not flow.get('handshake_complete')):
            return False
        if time.time() - self._local_ips_at > 60:
            self._local_ips, self._local_ips_at = _local_ips(), time.time()
        return flow['init_dst'] in self._local_ips

'''


def patch_pipeline(t):
    if "from scoring import" in t:
        raise PatchError("ids_pipeline.py already patched (found 'from scoring import')")

    t = sub_once(t,
        "from threat_evidence import save_threat_evidence\n",
        "from threat_evidence import save_threat_evidence\n"
        "import heapq\n"
        "from scoring import attack_probability, clamp_override, sanitize_settings\n",
        "imports")

    t = sub_once(t,
        "    RF_OVERRIDE_CONF = 0.90   # random forest alone -> high-confidence known attack\n",
        "    RF_OVERRIDE_CONF = 0.90   # random forest alone -> high-confidence known attack\n"
        "    MAX_ACTIVE_BLOCKS = 256   # bound iptables rule growth under a spoofed flood\n",
        "MAX_ACTIVE_BLOCKS")

    t = sub_once(t,
        "        self._settings_cache = {}\n",
        "        self._settings_cache = sanitize_settings({})\n"
        "        self.evicted_flows_total = 0\n",
        "__init__ settings/evicted")

    t = sub_once(t,
        "                    self._settings_cache = json.loads(stored)\n",
        "                    self._settings_cache = sanitize_settings(json.loads(stored))\n",
        "_load_settings sanitize")

    t = sub_once(t,
        "            if cal.get('ae_override') is not None:\n"
        "                ae = float(cal['ae_override'])\n"
        "            if cal.get('rf_override') is not None:\n"
        "                rf = float(cal['rf_override'])\n",
        "            new_ae, new_rf = ae, rf\n"
        "            if cal.get('ae_override') is not None:\n"
        "                new_ae = clamp_override(cal['ae_override'])\n"
        "            if cal.get('rf_override') is not None:\n"
        "                new_rf = clamp_override(cal['rf_override'])\n"
        "            ae, rf = new_ae, new_rf   # all-or-nothing: a bad value keeps both defaults\n",
        "_load_override_confs clamp")

    t = sub_once(t,
        "    def packet_callback(self, packet):\n",
        EVICT_OVERFLOW_NEW + "    def packet_callback(self, packet):\n",
        "_evict_overflow")

    t = sub_once(t,
        "                'init_syn': bool(TCP in packet and (int(packet[TCP].flags) & 0x12) == 0x02),\n",
        "                'init_syn': bool(TCP in packet and (int(packet[TCP].flags) & 0x12) == 0x02),\n"
        "                'synack_seq': None,\n"
        "                'handshake_complete': False,\n",
        "flow dict handshake fields")

    t = sub_once(t,
        "        flow['packet_list'].append((packet, is_forward))\n",
        HANDSHAKE_NEW,
        "handshake tracking")

    t = replace_between(t,
        "    def _inference_batch(self):\n",
        "    def _dump_features(self, keys, feats, errs, rf_probs):\n",
        INFERENCE_NEW,
        "_inference_batch/_score_flows")

    t = replace_between(t,
        "        ae_score = recon_error / (recon_error + self.recon_threshold)\n",
        "        if flow['packets'] >= 2:\n",
        FUSION_NEW,
        "fusion block")

    t = replace_between(t,
        "        # Sensitivity changes the minimum anomaly score needed to emit an alert.\n"
        "        # Severity thresholds below still decide the label (MEDIUM/HIGH/CRITICAL).\n",
        "        # The override_reason already boosted anomaly_score above, so this gate\n",
        "",
        "remove old cutoff block")

    t = replace_between(t,
        "    def _should_block(self, flow) -> bool:\n",
        "    def _load_autoblock_state(self):\n",
        SHOULD_BLOCK_NEW,
        "_should_block")
    return t


def patch_calibrate(t):
    if "from scoring import" in t:
        raise PatchError("calibrate_override.py already patched")

    t = sub_once(t,
        "from sequence_builder import build_cnn_sequences  # noqa: E402\n",
        "from sequence_builder import build_cnn_sequences  # noqa: E402\n"
        "from scoring import attack_probability  # noqa: E402\n",
        "calibrate imports")

    t = sub_once(t,
        "    attack = X_test[y_test == 1]\n",
        "    attack = X_test[y_test != 0]   # every attack class, not only class 1\n",
        "calibrate attack rows")

    t = sub_once(t,
        "        attack_idx = list(rf.classes_).index(1) if 1 in rf.classes_ else -1\n"
        "        benign_rf = rf.predict_proba(benign)[:, attack_idx]\n"
        "        rf_override = float(np.percentile(benign_rf, rf_pct))\n"
        "        rf_recall = (float((rf.predict_proba(attack)[:, attack_idx] > rf_override).mean())\n"
        "                     if len(attack) else float(\"nan\"))\n",
        "        benign_rf = attack_probability(rf.predict_proba(benign), rf.classes_)\n"
        "        rf_override = float(np.percentile(benign_rf, rf_pct))\n"
        "        rf_recall = (float((attack_probability(rf.predict_proba(attack), rf.classes_)\n"
        "                            > rf_override).mean())\n"
        "                     if len(attack) else float(\"nan\"))\n",
        "calibrate RF probability")

    t = sub_once(t,
        "    result = {\n",
        "    for name, val in ((\"ae_override\", ae_override), (\"rf_override\", rf_override)):\n"
        "        if val is not None and val < 0.75:\n"
        "            print(f\"\\nWARNING: {name}={val:.4f} is below the default alert cutoff 0.75. \"\n"
        "                  \"At medium sensitivity it cannot raise an alert on its own; the \"\n"
        "                  \"pipeline clamps anything below 0.50.\")\n"
        "\n"
        "    result = {\n",
        "calibrate low-override warning")
    return t


def main():
    for p in (PIPELINE, CALIBRATE):
        if not p.exists():
            sys.exit(f"Not found: {p}\nRun this script from the repository root.")

    try:
        pipe_text, pipe_crlf = read_lf(PIPELINE)
        cal_text, cal_crlf = read_lf(CALIBRATE)
        new_pipe = patch_pipeline(pipe_text)
        new_cal = patch_calibrate(cal_text)
    except PatchError as e:
        sys.exit(f"ABORTED, nothing written: {e}\n"
                 "Your file differs from the version reviewed. Paste the failing section.")

    shutil.copy2(PIPELINE, PIPELINE.with_suffix(".py.bak"))
    shutil.copy2(CALIBRATE, CALIBRATE.with_suffix(".py.bak"))
    SCORING.write_text(SCORING_SRC, encoding="utf-8")
    write_eol(PIPELINE, new_pipe, pipe_crlf)
    write_eol(CALIBRATE, new_cal, cal_crlf)

    print(f"Wrote   {SCORING.relative_to(ROOT)}")
    print(f"Patched {PIPELINE.relative_to(ROOT)}  (backup .py.bak)")
    print(f"Patched {CALIBRATE.relative_to(ROOT)}  (backup .py.bak)")
    print("\nNext:\n  python -m pytest backend/tests -q")


if __name__ == "__main__":
    main()