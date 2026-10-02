# backend/src/ids_pipeline.py
import logging
import os
import platform
import queue
from datetime import datetime
from typing import NamedTuple, Tuple
import numpy as np
from scapy.all import AsyncSniffer, sniff, IP, TCP, UDP
import subprocess
import json
import time
from collections import deque
import ipaddress
import threading
import heapq
import pandas as pd

from redis_util import make_redis
from threat_evidence import save_threat_evidence
from scoring import attack_probability, clamp_override, sanitize_settings

# NOTE: no logging.basicConfig() here. A basicConfig at import time runs before main.py's own
# setup and turns that one into a silent no-op (logs/ids.log was never written). Logging is
# configured exactly once, in main.py.
logger = logging.getLogger(__name__)


def _load_whitelist(config_path=None) -> set:
    """Combine IDS_WHITELIST with a local JSON whitelist; validate every address."""
    values = {x.strip() for x in os.environ.get("IDS_WHITELIST", "").split(",") if x.strip()}
    path = config_path or os.path.join(os.path.dirname(__file__), "..", "config", "whitelist.json")
    try:
        with open(path, encoding="utf-8") as f:
            values.update(str(x).strip() for x in json.load(f).get("whitelist", []) if str(x).strip())
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.warning(f"Could not load whitelist {path}: {e}")
    valid = set()
    for value in values:
        try:
            valid.add(str(ipaddress.ip_address(value)))
        except ValueError:
            logger.warning(f"Ignoring invalid whitelist IP: {value!r}")
    return valid


def _local_ips() -> set:
    """IPv4 addresses on this host's interfaces (tells inbound from outbound flows)."""
    try:
        import psutil
        return {a.address for addrs in psutil.net_if_addrs().values()
                for a in addrs if a.family.name == "AF_INET"}
    except Exception:
        return set()


def _fw(cmd):
    return subprocess.run(cmd, capture_output=True, timeout=10)


IDS_IPTABLES_COMMENT = "IDS-AUTOBLOCK"


def block_ip(ip) -> bool:
    """
    Install an IDS-owned inbound DROP rule for a public IP.

    IMPORTANT: only rules explicitly tagged as IDS-owned are ever removed later.
    A pre-existing generic DROP rule is treated as operator-owned and is never
    deleted by the IDS.
    """
    try:
        ip = str(ipaddress.ip_address(ip))
        if not ipaddress.ip_address(ip).is_global:
            logger.warning(f"[IPS] Refusing to block non-public address {ip}")
            return False
    except ValueError:
        return False

    system = platform.system().lower()
    try:
        if system == "linux":
            tagged = ["iptables", "-C", "INPUT", "-s", ip, "-m", "comment",
                      "--comment", IDS_IPTABLES_COMMENT, "-j", "DROP"]
            if _fw(tagged).returncode == 0:
                return True  # Already owned by this IDS.

            generic = _fw(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
            if generic.returncode == 0:
                logger.warning(
                    f"[IPS] {ip} is already blocked by an unowned firewall rule; "
                    "leaving it untouched."
                )
                return False

            # Insert at the front so an earlier ACCEPT rule cannot shadow the DROP.
            add = _fw(["iptables", "-I", "INPUT", "1", "-s", ip, "-m", "comment",
                       "--comment", IDS_IPTABLES_COMMENT, "-j", "DROP"])
            if add.returncode != 0:
                raise RuntimeError(add.stderr.decode(errors="replace").strip())
            logger.warning(f"!!! [IPS] Blocked malicious IP via IDS-owned iptables rule: {ip}")
            return True

        if system == "windows":
            name = f"Block_IDS_{ip}"
            show = _fw(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"])
            if show.returncode == 0:
                return True  # The deterministic IDS rule already exists.
            add = _fw(["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name={name}", "dir=in", "action=block", f"remoteip={ip}"])
            if add.returncode != 0:
                raise RuntimeError(add.stdout.decode(errors="replace").strip())
            logger.warning(f"!!! [IPS] Blocked malicious IP via IDS-owned Windows Firewall rule: {ip}")
            return True

        logger.warning(f"[IPS] Automatic blocking not implemented for platform '{system}' — "
                       f"IP {ip} was flagged CRITICAL but NOT blocked.")
    except Exception as e:
        logger.error(f"[IPS] Failed to block {ip} (missing NET_ADMIN / not root / not host "
                     f"network namespace?): {e}")
    return False


def unblock_ip(ip) -> None:
    """Remove only the IDS-owned firewall rule for ``ip``."""
    try:
        ip = str(ipaddress.ip_address(ip))
        system = platform.system().lower()
        if system == "linux":
            _fw(["iptables", "-D", "INPUT", "-s", ip, "-m", "comment",
                 "--comment", IDS_IPTABLES_COMMENT, "-j", "DROP"])
        elif system == "windows":
            _fw(["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name=Block_IDS_{ip}"])
        logger.warning(f"[IPS] Unblocked IDS-owned rule for {ip}")
    except Exception as e:
        logger.error(f"[IPS] Failed to unblock {ip}: {e}")


def _payload_len(p) -> int:
    """
    L4 payload bytes of one packet -- the quantity CICFlowMeter uses for every *Length* and
    *Bytes* feature (BasicFlow.addPacket feeds getPayloadBytes() into flowLengthStats,
    fwdPktStats, bwdPktStats and forwardBytes; headers are tracked separately).

    len(p) is NOT that. On an Ethernet capture it also counts the 14-byte Ethernet header plus
    the IP and TCP/UDP headers, so a bare SYN measures 54 bytes live where CICIDS records 0.
    Ethernet minimum-frame padding (Scapy exposes it inside the TCP payload) is ignored too.
    """
    ip = p[IP]
    total = ip.len or len(ip)
    ihl = (ip.ihl or 5) * 4
    if TCP in p:
        l4 = (p[TCP].dataofs or 5) * 4
    elif UDP in p:
        l4 = 8
    else:
        return 0
    return max(int(total) - ihl - l4, 0)


class PacketSummary(NamedTuple):
    """Everything the feature extractor reads from one packet. Replaces retained Scapy objects."""
    ts: float        # capture timestamp, seconds
    fwd: bool        # direction relative to the flow initiator
    plen: int        # L4 payload bytes (CICFlowMeter semantics, see _payload_len)
    hlen: int        # L4 header bytes
    flags: int       # raw TCP flags byte; 0 for UDP
    is_tcp: bool


# TCP flag bits as CICFlowMeter counts them.
_FLAG_BITS = dict(fin=0x01, syn=0x02, rst=0x04, psh=0x08, ack=0x10, urg=0x20, ece=0x40, cwe=0x80)


def summarize(packet):
    """
    The single Scapy -> plain-data boundary. Returns None for anything that is not
    IPv4 TCP/UDP, otherwise:
        ((src, sport, dst, dport, proto), wire_len, window, seq, ack,
         (ts, payload_len, header_len, flags, is_tcp))
    Direction is resolved at ingest, once the flow exists. seq/ack are consumed there
    for handshake verification and never stored.
    """
    if IP not in packet:
        return None
    ip = packet[IP]
    if TCP in packet:
        t = packet[TCP]
        sport, dport, is_tcp = int(t.sport), int(t.dport), True
        flags, win, seq, ack = int(t.flags), int(t.window), int(t.seq), int(t.ack)
        hlen = (t.dataofs or 5) * 4
    elif UDP in packet:
        u = packet[UDP]
        sport, dport, is_tcp = int(u.sport), int(u.dport), False
        flags, win, seq, ack, hlen = 0, None, 0, 0, 8
    else:
        return None
    return ((ip.src, sport, ip.dst, dport, int(ip.proto)), len(packet), win, seq, ack,
            (float(packet.time), _payload_len(packet), hlen, flags, is_tcp))


def _as_summary(entry, flow) -> PacketSummary:
    """
    Accept a PacketSummary, or a legacy (scapy_packet, is_forward) tuple built by
    older tests/fixtures. Legacy entries go through the same summarize() boundary,
    so reference-fixture tests exercise the production feature path.
    """
    if isinstance(entry, PacketSummary):
        return entry
    packet, is_fwd = entry
    s = summarize(packet)
    if s is None:
        raise ValueError("packet_list entry is not IPv4 TCP/UDP")
    ts, plen, hlen, fl, is_tcp = s[5]
    return PacketSummary(ts, bool(is_fwd), plen, hlen, fl, is_tcp)


class RealTimeIDSPipeline:
    """
    Orchestrates real-time packet capture → feature extraction → AI inference → alerting.

    Threading model:
      * capture thread (Scapy sniff callback): summarize packet, enqueue. Nothing else.
      * scoring worker: owns flow state, batching, inference, alerting, firewall calls.
      * ticker: health reporting only.
    When self._queue is None (tests, offline replay) packets are processed synchronously.
    """

    # Confidence-override fusion thresholds (see _process_prediction). A single
    # model this confident overrides the 0.5/0.5 average so neither detector can
    # fully veto the other.
    AE_OVERRIDE_CONF = 0.97   # autoencoder alone -> possible novel/unknown attack
    RF_OVERRIDE_CONF = 0.90   # random forest alone -> high-confidence known attack
    MAX_ACTIVE_BLOCKS = 256   # bound iptables rule growth under a spoofed flood

    # CICFlowMeter V4 uses a 1-second activity/bulk/subflow boundary. Separate from
    # the IDS flow timeout (an operational eviction bound, not a feature definition).
    CICFLOWMETER_ACTIVITY_TIMEOUT_US = 1_000_000

    # Active/Idle uses the flow's activityTimeout, which is 5 s in the CICIDS2017 data:
    # the smallest non-zero 'Idle Min' in the Friday-DDoS CSV is 5,000,005 us and no idle
    # value lies between 1 s and 5 s. Using the 1 s bulk/subflow boundary here would emit
    # idle gaps the models never saw in training.
    CICFLOWMETER_ACTIVE_IDLE_TIMEOUT_US = 5_000_000

    # The six Bulk columns are exactly 0 in every row of the CICIDS2017 training CSV
    # (known CICFlowMeter output quirk), so the scaler has zero range for them and would
    # pass a live value such as 333333 through unscaled. They are computed in
    # _extract_flow_features (kept CICFlowMeter-faithful) but zeroed before scaling so the
    # model sees the same input distribution it was trained on.
    TRAINING_ZERO_FEATURES = (
        "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
        # Bwd PSH Flags has scaler max 0 in training (always 0); a live count would pass unscaled.
        "Bwd PSH Flags",
        # Same zero-range scaler columns (data_min_ = data_max_ = 0), found by the 1 Oct 2026 review.
        "Fwd URG Flags", "Bwd URG Flags", "CWE Flag Count",
    )

    # An autoencoder override the Random Forest did not confirm is capped at this severity,
    # so it never reaches CRITICAL (and therefore never triggers AutoBlock). Measured on a
    # 56-minute live benign capture (benign_long.csv, 1 Oct 2026): every false alert came
    # from this override (0.5% of flows, ~8.5 alerts/h, 3 of 8 CRITICAL on large downloads).
    AE_OVERRIDE_MAX_SEVERITY = "MEDIUM"

    # A Random Forest P(attack) above RF_ALERT_CONF alerts on its own even when the fused score
    # stays under the cutoff, at a fixed MEDIUM severity (never CRITICAL -> never AutoBlock).
    # CICIDS2017 Friday pcap replay through the live pipeline (2 Oct 2026): recall 84.16% ->
    # 98.72% on 96,811 DDoS flows, 0 false alerts on 22,951 other flows, and no new alerts on
    # 81.5 min / 2,695 flows of live laptop traffic.
    RF_ALERT_CONF = 0.70
    RF_MODERATE_SEVERITY = "MEDIUM"

    # Per-source connection RATE. Per-flow features cannot express "how many connections per
    # second": one flood connection looks like one normal request (2 Oct 2026: live_flow_v2
    # flagged 99% of human-paced GETs). Measured peak new connections/s per source (10 s window):
    # normal laptop use <= 4.3, normal WSL use <= 2.5; Wi-Fi lab flood 87, WSL flood 247,
    # CICIDS2017 DDoS replay 116. Counts new TCP connections only (UDP/DNS excluded).
    #  * RF-driven verdicts (RF P(attack) > 0.5) only alert from a source >= RF_MIN_SRC_RATE.
    #  * A source >= RATE_FLOOD_CONN_PER_S alerts by itself, model-independent, at HIGH.
    RATE_WINDOW_S = 10.0
    RF_MIN_SRC_RATE = 10.0
    RATE_FLOOD_CONN_PER_S = 30.0
    RATE_FLOOD_SEVERITY = "HIGH"
    RATE_GATED_CLASSES = frozenset({"DoS", "DDoS"})      # multi-class RF classes that must flood

    # In the CICIDS2017 Friday CSV these flag columns only ever hold 0 or 1 (scaler max = 1),
    # i.e. flag *presence*, whereas BasicFlow.java and _extract_flow_features count packets
    # (live SYN=2, ACK=8, ...). Measured on lab_run2.csv (1 Oct 2026): feeding the raw counts
    # put 86-96% of flows above the training max and made the autoencoder score every flood
    # flow as an override; clamping to presence removed that artefact. Clamped before scaling.
    TRAINING_BINARY_FEATURES = (
        "Fwd PSH Flags", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
        "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "ECE Flag Count",
    )

    UNSUPPORTED_LIVE_FEATURES = ()

    def __init__(self,
                 model_path: str,
                 feature_extractor_path: str,
                 alert_threshold: float = 0.75,
                 packet_batch_size: int = 100,
                 flow_idle_timeout: float = 120.0,
                 max_tracked_flows: int = 20000,
                 flow_max_duration: float = 120.0,
                 max_packets_per_flow: int = 2000,
                 batch_interval: float = 2.0,
                 alert_cooldown: float = 60.0,
                 block_ttl: float = 900.0,
                 sweep_interval: float = 1.0):
        self.model_path = model_path
        self.alert_threshold = alert_threshold
        self.packet_batch_size = packet_batch_size
        # Flow-table eviction bounds:
        #   - flow_idle_timeout: seconds since last packet before a flow is finished.
        #   - max_tracked_flows: hard cap; oldest flows are scored then evicted
        #     (safety net against high-cardinality floods).
        self.flow_idle_timeout = flow_idle_timeout
        self.flow_max_duration = flow_max_duration
        self.max_packets_per_flow = max_packets_per_flow
        self.batch_interval = batch_interval
        self.alert_cooldown = alert_cooldown
        self.block_ttl = block_ttl
        self.sweep_interval = sweep_interval
        self._last_batch_at = time.time()
        self._capture_health_at = time.monotonic()
        self._capture_packets = 0
        self._capture_ipv4_transport_packets = 0
        self.max_tracked_flows = max_tracked_flows
        self._last_eviction_at = 0.0

        try:
            self.redis_client = make_redis()
            self.redis_client.ping()
            logger.info("Redis connected successfully")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Alerts won't be persisted.")
            self.redis_client = None

        try:
            # Live detection is a two-model ensemble:
            #   - Autoencoder (unsupervised): reconstruction error vs benign training.
            #   - Random Forest (supervised): known attack patterns.
            # The CNN is intentionally NOT loaded: it classifies sequences of 100
            # consecutive CSV rows (sequence_builder.py), which has no live equivalent.
            # It is an offline comparison model only (model_evaluation.py).
            import tensorflow as tf
            from joblib import load

            self.autoencoder = tf.keras.models.load_model(model_path, compile=False)
            self.feature_scaler = load(feature_extractor_path)
            logger.info("Autoencoder + feature scaler loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            raise

        # Supervised second opinion. Optional: if it can't load, AE-only mode
        # (which is itself gated by IDS_AE_ONLY_ALERTING_VALIDATED).
        self.random_forest = None
        self._rf_attack_idx = None
        self._rf_multiclass = False
        # IDS_RF_DIR (opt-in) loads random_forest.pkl + label_map.json from another directory,
        # e.g. a model trained on live captures by train_live_flow.py. Relative paths resolve
        # against the models directory. Unset = the shipped CICIDS2017 RF next to the AE.
        models_dir = os.path.dirname(model_path)
        self.rf_dir = os.path.join(models_dir, os.environ.get("IDS_RF_DIR", "").strip() or ".")
        self.rf_dir = os.path.normpath(self.rf_dir)
        try:
            from joblib import load
            rf_path = os.path.join(self.rf_dir, 'random_forest.pkl')
            logger.info(f"Random Forest source: {rf_path}")
            self.random_forest = load(rf_path)
            classes = list(self.random_forest.classes_)
            if 0 not in classes:
                raise ValueError(f"RF has no benign class 0 (classes={classes}); "
                                 "P(attack) = 1 - P(benign) cannot be computed")
            self._rf_attack_idx = classes.index(1) if 1 in classes else len(classes) - 1
            self._rf_multiclass = len(classes) > 2
            mode = "multi-class" if self._rf_multiclass else "binary"
            logger.info(f"Random Forest loaded ({mode}, classes={classes}) — supervised cross-check enabled")
        except Exception as e:
            self.random_forest = None
            logger.warning(f"Random Forest not loaded ({e}); live detection will use the autoencoder alone")

        # Attack-type label map written by preprocess_pipeline(multiclass=True).
        self._label_map = {}
        label_map_path = os.path.join(self.rf_dir, 'label_map.json')
        try:
            with open(label_map_path) as f:
                self._label_map = {int(k): v for k, v in json.load(f).items()}
            logger.info(f"Loaded {len(self._label_map)}-class label map from {label_map_path}: "
                        + ", ".join(f"{k}={v}" for k, v in sorted(self._label_map.items())))
        except FileNotFoundError:
            if self._rf_multiclass:
                logger.warning(f"Multi-class RF loaded but no label_map.json at {label_map_path}; "
                               "threat names will fall back to class integers. Re-run preprocessing "
                               "with --multiclass to regenerate the map.")
        except Exception as e:
            logger.warning(f"Could not load label map ({e}); threat names will be generic")

        self.recon_threshold, self._threshold_calibrated = self._load_recon_threshold(model_path)
        self.AE_OVERRIDE_CONF, self.RF_OVERRIDE_CONF = self._load_override_confs(model_path)
        self.RF_MIN_SRC_RATE, self.RATE_FLOOD_CONN_PER_S = self._load_rate_thresholds()

        # AE-only detection is intentionally opt-in (requires live-lab validation).
        self.ae_only_alerting_validated = (
            os.environ.get("IDS_AE_ONLY_ALERTING_VALIDATED", "false").strip().lower()
            in {"1", "true", "yes"}
        )
        if self.random_forest is None and not self.ae_only_alerting_validated:
            logger.warning(
                "AE-only alerting is disabled until IDS_AE_ONLY_ALERTING_VALIDATED=true. "
                "Capture and validate controlled live-lab traffic first."
            )
        self._ae_only_suppressed = 0   # counted, logged once, not per flow
        self.evidence_origin = os.environ.get("IDS_EVIDENCE_ORIGIN", "live_unclassified")

        self.packet_buffer = []
        self.flow_tracker = {}
        self._settings_cache = sanitize_settings({})
        self._settings_loaded_at = 0.0
        self.evicted_flows_total = 0
        self._last_alert = {}          # (src_ip, severity) -> (last_alert_ts, suppressed_count)
        self._lock = threading.RLock() # worker and flush()/tests share flow state
        self._capture_counter_lock = threading.Lock()
        self._done = set()             # flow keys flagged finished (FIN/RST/packet cap)
        self._last_sweep_at = 0.0
        self._blocked = {}             # ip -> unblock-at epoch
        self._autoblock_state_path = os.environ.get(
            "IDS_AUTOBLOCK_STATE",
            os.path.join(os.path.dirname(__file__), "..", "evidence", "autoblock_state.json"),
        )
        self._load_autoblock_state()
        self._local_ips = _local_ips()
        self._local_ips_at = time.time()
        self._whitelist = _load_whitelist()
        self._stop = threading.Event()
        # IDS_DUMP_FEATURES=<file.csv>: append every scored flow's raw features. Off by default.
        self._dump_path = os.environ.get("IDS_DUMP_FEATURES") or None
        self._dump_rows = 0
        self._dump_max = int(os.environ.get("IDS_DUMP_MAX_ROWS", "200000"))
        # Capture -> worker handoff. Bounded: on overflow packets are dropped and
        # counted (reported in CAPTURE_HEALTH), never silently lost.
        self._queue = queue.Queue(maxsize=int(os.environ.get("IDS_QUEUE_MAX", "50000")))
        self._dropped_packets = 0
        self._worker_thread = None

    @staticmethod
    def _load_recon_threshold(model_path: str):
        """Reads the benign-calibrated reconstruction threshold. Returns (threshold, is_calibrated)."""
        metrics_path = os.path.join(os.path.dirname(model_path), 'real_metrics.json')
        try:
            with open(metrics_path) as f:
                metrics = json.load(f)
            threshold = metrics.get('autoencoder', {}).get('threshold')
            if threshold:
                logger.info(f"Loaded calibrated reconstruction-error threshold: {threshold:.6f} "
                            f"(from {metrics_path})")
                return float(threshold), True
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning(f"Could not parse {metrics_path}: {e}")

        fallback = 1.0
        logger.warning(
            f"No calibrated reconstruction-error threshold found at {metrics_path}. "
            f"Using an UNCALIBRATED fallback ({fallback}) — severity scores will be "
            f"meaningless until you run `python src/model_evaluation.py <preprocessed_csv>`."
        )
        return fallback, False

    @classmethod
    def _load_rate_thresholds(cls, env=None):
        """IDS_RF_MIN_SRC_RATE / IDS_RATE_FLOOD_CONN_PER_S override the measured defaults so a
        site can calibrate them (backend/calibrate_rate.py). Invalid values fall back to the
        defaults with a warning; the flood threshold may not be below the RF gate."""
        env = os.environ if env is None else env
        def read(name, default):
            raw = (env.get(name) or "").strip()
            if not raw:
                return default
            try:
                v = float(raw)
                if v > 0:
                    return v
            except ValueError:
                pass
            logger.warning(f"Ignoring invalid {name}={raw!r}; using {default}")
            return default
        gate = read("IDS_RF_MIN_SRC_RATE", cls.RF_MIN_SRC_RATE)
        flood = read("IDS_RATE_FLOOD_CONN_PER_S", cls.RATE_FLOOD_CONN_PER_S)
        if flood < gate:
            logger.warning(f"IDS_RATE_FLOOD_CONN_PER_S={flood} is below the RF gate {gate}; "
                           f"using defaults {cls.RF_MIN_SRC_RATE}/{cls.RATE_FLOOD_CONN_PER_S}")
            return cls.RF_MIN_SRC_RATE, cls.RATE_FLOOD_CONN_PER_S
        if (gate, flood) != (cls.RF_MIN_SRC_RATE, cls.RATE_FLOOD_CONN_PER_S):
            logger.info(f"Connection-rate thresholds from environment: RF gate {gate}/s, "
                        f"flood alert {flood}/s")
        return gate, flood

    @classmethod
    def _load_override_confs(cls, model_path: str):
        """
        Reads override thresholds from models/override_calibration.json, falling back
        to the class defaults. Values below scoring.OVERRIDE_FLOOR are clamped.
        """
        ae, rf = cls.AE_OVERRIDE_CONF, cls.RF_OVERRIDE_CONF
        path = os.path.join(os.path.dirname(model_path), 'override_calibration.json')
        try:
            with open(path) as f:
                cal = json.load(f)
            new_ae, new_rf = ae, rf
            if cal.get('ae_override') is not None:
                new_ae = clamp_override(cal['ae_override'])
            if cal.get('rf_override') is not None:
                new_rf = clamp_override(cal['rf_override'])
            ae, rf = new_ae, new_rf
            logger.info(f"Loaded override thresholds (effective, post-clamp) "
                        f"(ae={ae:.4f}, rf={rf:.4f}) from {path}")
        except FileNotFoundError:
            logger.info(f"No override_calibration.json — using coded override "
                        f"defaults (ae={ae:.2f}, rf={rf:.2f}).")
        except Exception as e:
            logger.warning(f"Could not parse {path}: {e}; using coded override defaults")
        return ae, rf

    def _load_settings(self) -> dict:
        """Re-read sanitized Settings-page config from Redis at most every 5 s."""
        now = time.time()
        if self.redis_client and (now - self._settings_loaded_at) > 5:
            try:
                stored = self.redis_client.get('ids:settings')
                if stored:
                    self._settings_cache = sanitize_settings(json.loads(stored))
            except Exception as e:
                logger.debug(f"Could not refresh live settings: {e}")
            self._settings_loaded_at = now
        return self._settings_cache

    def _evict_stale_flows(self):
        """Legacy idle + hard-cap sweep (unscored). Kept for existing callers/tests only."""
        now = datetime.now()
        stale = [
            k for k, f in self.flow_tracker.items()
            if (now - f['last_seen']).total_seconds() > self.flow_idle_timeout
        ]
        for k in stale:
            del self.flow_tracker[k]

        overflow = len(self.flow_tracker) - self.max_tracked_flows
        if overflow > 0:
            oldest = sorted(
                self.flow_tracker.items(), key=lambda kv: kv[1]['last_seen']
            )[:overflow]
            for k, _ in oldest:
                del self.flow_tracker[k]
            logger.warning(
                f"flow_tracker hit max_tracked_flows ({self.max_tracked_flows}); "
                f"evicted {overflow} oldest flows (possible high-cardinality flood)."
            )

        if stale or overflow > 0:
            logger.debug(
                f"Flow eviction: dropped {len(stale)} idle + "
                f"{max(overflow, 0)} over-cap; {len(self.flow_tracker)} flows tracked."
            )

    def _evict_overflow(self) -> int:
        """Hard cap: SCORE the oldest overflow flows, then drop them (always, via finally)."""
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

    # ------------------------------------------------------------------ capture / ingest

    def packet_callback(self, packet):
        """Capture thread: summarize and hand off. No flow state, no inference, no subprocess."""
        s = summarize(packet)
        with self._capture_counter_lock:
            self._capture_packets += 1
            if s is not None:
                self._capture_ipv4_transport_packets += 1
        if s is None:
            return
        if self._queue is None:            # synchronous mode (tests / offline replay)
            self._process_summary(s)
            return
        try:
            self._queue.put_nowait(s)
        except queue.Full:
            with self._capture_counter_lock:
                self._dropped_packets += 1

    def _process_summary(self, s):
        with self._lock:
            self._ingest_summary(s)
            if (len(self.packet_buffer) >= self.packet_batch_size
                    or time.time() - self._last_batch_at >= self.batch_interval):
                self._inference_batch()

    def _ingest(self, packet):
        """Back-compat for callers/tests that pass Scapy packets directly."""
        s = summarize(packet)
        if s is not None:
            self._ingest_summary(s)

    def _ingest_summary(self, s):
        (src_ip, src_port, dst_ip, dst_port, protocol), wire_len, win, seq, ack, part = s
        ts, plen, hlen, fl, is_tcp = part
        flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (protocol,)

        now = datetime.now()
        flow = self.flow_tracker.get(flow_key)
        if flow is None and is_tcp and (fl & 0x04):
            # A RST never starts a connection. It arrives after the flow already closed on FIN
            # (and was scored and dropped), and would otherwise become a 1-packet "flow".
            # CIC pcap replay, 2 Oct 2026: 47% of DDoS flows were such RST+ACK fragments, while
            # the CICIDS2017 CSV has 0% one-packet flows. Count them instead of scoring them.
            self._orphan_rst_packets = getattr(self, "_orphan_rst_packets", 0) + 1
            return
        if flow is None:
            # A SYN-ACK is always sent by the server. If capture missed the client's SYN
            # (drops, capture start mid-handshake), the first packet seen is the SYN-ACK and
            # "first packet = initiator" would name the VICTIM as the source (seen on the
            # 1 Oct 2026 WSL flood run: 1,259 flows). Orient the flow from the client instead.
            # init_syn stays False, so AutoBlock still requires a proven bare SYN.
            i_src, i_sport, i_dst, i_dport = src_ip, src_port, dst_ip, dst_port
            if is_tcp and (fl & 0x12) == 0x12:
                i_src, i_sport, i_dst, i_dport = dst_ip, dst_port, src_ip, src_port
            if is_tcp:
                # TCP only: on the CICIDS2017 replay, busy workstations sent 34-57 DNS (UDP)
                # queries/s, which a combined count turned into 5,577 false rate alerts.
                self._note_new_flow(i_src, ts)
            flow = self.flow_tracker[flow_key] = {
                'packets': 0,
                'bytes': 0,
                'first_seen': now,
                'last_seen': now,
                'protocol': protocol,
                'packet_list': [],
                # The first packet observed defines "forward" (client side if it was a SYN-ACK).
                'init_src': i_src,
                'init_sport': i_sport,
                'init_dst': i_dst,
                'init_dport': i_dport,
                'fwd_win': None,
                'bwd_win': None,
                'done': False,
                # True only if the first packet seen was a bare SYN.
                'init_syn': bool(is_tcp and (fl & 0x12) == 0x02),
                'synack_seq': None,
                'handshake_complete': False,
            }

        flow['packets'] += 1
        flow['bytes'] += wire_len
        flow['last_seen'] = now

        is_forward = (src_ip == flow['init_src'] and src_port == flow['init_sport'])
        if is_tcp:
            if is_forward and flow['fwd_win'] is None:
                flow['fwd_win'] = win
            elif not is_forward:
                # CICFlowMeter-compatible: Init_Win_bytes_backward ends as the last
                # observed backward window.
                flow['bwd_win'] = win
            # Handshake verification for AutoBlock. A blind spoofer never receives our
            # SYN-ACK, so it cannot send a forward ACK acknowledging synack_seq + 1.
            if (not is_forward and flow['init_syn'] and (fl & 0x12) == 0x12
                    and flow['synack_seq'] is None):
                flow['synack_seq'] = seq
            elif (is_forward and flow['synack_seq'] is not None
                    and not flow['handshake_complete'] and (fl & 0x12) == 0x10
                    and ack == (flow['synack_seq'] + 1) % 2**32):
                flow['handshake_complete'] = True

        flow['packet_list'].append(PacketSummary(ts, is_forward, plen, hlen, fl, is_tcp))

        # Finished = FIN/RST seen or packet cap hit (age and idle are checked in the sweep).
        if (is_tcp and (fl & 0x05)) or flow['packets'] >= self.max_packets_per_flow:
            flow['done'] = True
        if flow['done']:
            self._done.add(flow_key)

        self.packet_buffer.append(flow_key)   # only len() is used

    def _collect_finished_flows(self):
        """Keys of flows ready to be scored exactly once."""
        keys = set(self._done)
        self._done.clear()
        t = time.time()
        if t - self._last_sweep_at >= self.sweep_interval:
            self._last_sweep_at = t
            now = datetime.now()
            for k, f in self.flow_tracker.items():
                if (f.get('done')
                        or (now - f['last_seen']).total_seconds() > self.flow_idle_timeout
                        or (now - f['first_seen']).total_seconds() >= self.flow_max_duration):
                    keys.add(k)
        return [k for k in keys if k in self.flow_tracker]

    def _inference_batch(self):
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
            for k in finished:
                self.flow_tracker.pop(k, None)
            try:
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
        features_df = pd.DataFrame(features_array, columns=feature_names)
        for _col in self.TRAINING_ZERO_FEATURES:
            if _col in features_df.columns:
                features_df[_col] = 0.0
        for _col in self.TRAINING_BINARY_FEATURES:
            if _col in features_df.columns:
                features_df[_col] = (features_df[_col] > 0).astype(np.float32)
        features_normalized = self.feature_scaler.transform(features_df)

        reconstructed = self.autoencoder.predict(
            features_normalized,
            batch_size=len(features_normalized),
            verbose=0
        )

        sq = np.square(features_normalized - reconstructed)
        recon_errors = np.mean(sq, axis=1)

        if logger.isEnabledFor(logging.DEBUG):
            names = self.feature_scaler.feature_names_in_
            for i, k in enumerate(flow_keys_batch):
                top = np.argsort(sq[i])[-3:][::-1]
                logger.debug("TOPFEAT %s -> %s", k,
                             ", ".join(f"{names[j]}={features_normalized[i, j]:.1f}" for j in top))

        rf_attack_probs = [None] * len(flow_keys_batch)
        threat_names = [None] * len(flow_keys_batch)
        if self.random_forest is not None:
            try:
                rf_input = features_normalized
                if hasattr(self.random_forest, "feature_names_in_"):
                    # RFs fitted on a DataFrame (train_live_flow.py) warn on every batch otherwise.
                    rf_input = pd.DataFrame(features_normalized,
                                            columns=self.random_forest.feature_names_in_)
                proba = self.random_forest.predict_proba(rf_input)
                rf_attack_probs = attack_probability(proba, self.random_forest.classes_)
                if self._rf_multiclass:
                    preds = self.random_forest.predict(rf_input)
                    threat_names = [
                        self._label_map.get(int(p), f"Class {p}") for p in preds
                    ]
                elif 1 in self._label_map:
                    # Binary RF: name the attack class only when the RF itself says attack.
                    threat_names = [self._label_map[1] if p is not None and p > 0.5 else None
                                    for p in rf_attack_probs]
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

    def _dump_features(self, keys, feats, errs, rf_probs):
        """Best-effort CSV append; must never break inference. Contains IPs -- keep it private."""
        try:
            import csv
            names = list(getattr(self.feature_scaler, "feature_names_in_",
                                 [f"f{i}" for i in range(feats.shape[1])]))
            new_file = not os.path.exists(self._dump_path)
            with open(self._dump_path, "a", newline="") as fh:
                w = csv.writer(fh)
                if new_file:
                    w.writerow(["ts", "evidence_origin", "feature_coverage", "src_ip", "dst_ip",
                                "dst_port", "protocol", "packets"] + names + ["recon_error", "rf_prob"])
                for k, x, e, rp in zip(keys, feats, errs, rf_probs):
                    f = self.flow_tracker.get(k)
                    if f is None:
                        continue
                    w.writerow([int(time.time()), self.evidence_origin,
                                self._live_feature_coverage(), f["init_src"], f["init_dst"], f["init_dport"],
                                f["protocol"], f["packets"], *[float(v) for v in x], float(e),
                                "" if rp is None else float(rp)])
                    self._dump_rows += 1
            if self._dump_rows >= self._dump_max:
                logger.warning(f"IDS_DUMP_FEATURES reached {self._dump_max} rows; dumping stopped.")
                self._dump_path = None
        except Exception as e:
            logger.warning(f"Feature dump failed, disabling it: {e}")
            self._dump_path = None

    def _live_feature_coverage(self):
        """Fraction of the deployed feature schema measured by this live extractor."""
        total = int(getattr(self.feature_scaler, "n_features_in_", 78))
        return max(0.0, (total - len(self.UNSUPPORTED_LIVE_FEATURES)) / total)

    def flush(self):
        """Score every finished flow now (used by verify_ensemble.py, tests, shutdown)."""
        with self._lock:
            self._inference_batch()

    # ------------------------------------------------------------------ background threads

    def _tick_once(self):
        """
        Report capture health every 10 s. Time-based flushing belongs to the scoring
        worker; when no worker is running (sync mode / tests) the ticker does it.
        """
        self._report_health()
        if self._worker_thread is None:
            with self._lock:
                if time.time() - self._last_batch_at >= self.batch_interval:
                    self._inference_batch()

    def _report_health(self):
        now = time.monotonic()
        if now - self._capture_health_at < 10.0:
            return
        with self._capture_counter_lock:
            packets = self._capture_packets
            ipv4_transport = self._capture_ipv4_transport_packets
            dropped = self._dropped_packets
            self._capture_packets = 0
            self._capture_ipv4_transport_packets = 0
            self._dropped_packets = 0
            self._capture_health_at = now

        if self._lock.acquire(blocking=False):
            try:
                tracked_flows = len(self.flow_tracker)
                buffered_packets = len(self.packet_buffer)
            finally:
                self._lock.release()
        else:
            tracked_flows = -1
            buffered_packets = -1

        qdepth = self._queue.qsize() if self._queue is not None else 0
        logger.info(
            "CAPTURE_HEALTH packets=%d ipv4_tcp_udp=%d dropped=%d qdepth=%d "
            "tracked_flows=%d buffered_packets=%d",
            packets, ipv4_transport, dropped, qdepth, tracked_flows, buffered_packets,
        )
        if dropped:
            logger.warning(f"Scoring worker fell behind: dropped {dropped} packets in the last "
                           "interval; features of affected flows are incomplete.")

    def _ticker(self):
        while not self._stop.wait(self.batch_interval):
            try:
                self._tick_once()
            except Exception as e:
                logger.error(f"Health ticker error: {e}", exc_info=True)

    def _worker(self):
        """Scoring worker: ingest queued summaries; flush on batch size or batch interval."""
        logger.info("Scoring worker started")
        while not self._stop.is_set():
            try:
                s = self._queue.get(timeout=self.batch_interval)
            except queue.Empty:
                try:
                    with self._lock:
                        self._inference_batch()      # time-based flush of idle flows
                except Exception as e:
                    logger.error(f"Worker flush error: {e}", exc_info=True)
                continue
            try:
                self._process_summary(s)
            except Exception as e:
                logger.error(f"Worker ingest error: {e}", exc_info=True)

    def _capture_heartbeat(self):
        """Report capture process liveness without taking the inference lock."""
        logger.info("CAPTURE_HEARTBEAT started")
        while not self._stop.wait(10.0):
            logger.info("CAPTURE_HEARTBEAT alive")

    # ------------------------------------------------------------------ features

    def _extract_flow_features(self, flow_key: Tuple) -> np.ndarray:
        """Extract the deployed 78-feature CICFlowMeter/CICIDS representation.

        Mirrors CICFlowMeter V4's BasicFlow.java/FlowFeature.java as closely as
        possible from the PacketSummary records retained per flow. Training-artifact
        version parity still must be verified before this extractor is used for
        retraining.

        *Flag Count* features are packet counts, not booleans. SummaryStatistics
        std-dev is sample std-dev (ddof=1).
        """
        if flow_key not in self.flow_tracker:
            return None

        flow = self.flow_tracker[flow_key]
        entries = flow['packet_list']
        if not entries:
            return None

        # Deterministic timestamp order (capture order is normally chronological).
        entries = sorted((_as_summary(e, flow) for e in entries), key=lambda s: s.ts)
        fwd_pkts = [s for s in entries if s.fwd]
        bwd_pkts = [s for s in entries if not s.fwd]
        all_pkts = entries

        def _sample_std(values):
            return float(np.std(values, ddof=1)) if len(values) > 1 else 0.0

        def _iat_stats(pkts):
            if len(pkts) < 2:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            times = np.sort(np.array([p.ts for p in pkts], dtype=np.float64))
            iat = np.diff(times) * 1_000_000.0
            return (float(iat.sum()), float(iat.mean()), _sample_std(iat),
                    float(iat.max()), float(iat.min()))

        packet_times = np.array([p.ts for p in all_pkts], dtype=np.float64)
        flow_duration_s = max(float(packet_times[-1] - packet_times[0]), 0.0)
        flow_duration_us = flow_duration_s * 1_000_000.0
        duration_s_safe = flow_duration_s if flow_duration_s > 0 else 0.001

        total_fwd_packets = len(fwd_pkts)
        total_bwd_packets = len(bwd_pkts)

        fwd_lengths = np.array([p.plen for p in fwd_pkts], dtype=np.float64)
        bwd_lengths = np.array([p.plen for p in bwd_pkts], dtype=np.float64)
        # Verified against backend/BasicFlow.java: firstPacket() calls
        # flowLengthStats.addValue() once unconditionally (line 129) and again inside the
        # forward/backward branch (lines 142/156), so the first packet is counted twice in
        # the flow-wide length stats. This mirrors CICFlowMeter, which generated the
        # training data; do not 'fix' it.
        all_lengths = np.array(
            [all_pkts[0].plen] + [p.plen for p in all_pkts],
            dtype=np.float64,
        )

        total_len_fwd = float(fwd_lengths.sum()) if len(fwd_lengths) else 0.0
        total_len_bwd = float(bwd_lengths.sum()) if len(bwd_lengths) else 0.0

        fwd_pkt_max = float(fwd_lengths.max()) if len(fwd_lengths) else 0.0
        fwd_pkt_min = float(fwd_lengths.min()) if len(fwd_lengths) else 0.0
        fwd_pkt_mean = float(fwd_lengths.mean()) if len(fwd_lengths) else 0.0
        fwd_pkt_std = _sample_std(fwd_lengths)
        bwd_pkt_max = float(bwd_lengths.max()) if len(bwd_lengths) else 0.0
        bwd_pkt_min = float(bwd_lengths.min()) if len(bwd_lengths) else 0.0
        bwd_pkt_mean = float(bwd_lengths.mean()) if len(bwd_lengths) else 0.0
        bwd_pkt_std = _sample_std(bwd_lengths)

        total_bytes = total_len_fwd + total_len_bwd
        num_packets = len(all_pkts)
        flow_bytes_per_s = total_bytes / duration_s_safe
        flow_packets_per_s = num_packets / duration_s_safe
        fwd_packets_per_s = total_fwd_packets / duration_s_safe
        bwd_packets_per_s = total_bwd_packets / duration_s_safe

        _, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(all_pkts)
        fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(fwd_pkts)
        bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(bwd_pkts)

        def _flag_counts(pkts):
            return {n: sum(1 for s in pkts if s.is_tcp and s.flags & b)
                    for n, b in _FLAG_BITS.items()}

        fwd_flags = _flag_counts(fwd_pkts)
        bwd_flags = _flag_counts(bwd_pkts)
        all_flags = _flag_counts(all_pkts)

        fwd_header_len = float(sum(p.hlen for p in fwd_pkts))
        bwd_header_len = float(sum(p.hlen for p in bwd_pkts))

        min_pkt_len = float(all_lengths.min()) if len(all_lengths) else 0.0
        max_pkt_len = float(all_lengths.max()) if len(all_lengths) else 0.0
        pkt_len_mean = float(all_lengths.mean()) if len(all_lengths) else 0.0
        pkt_len_std = _sample_std(all_lengths)
        pkt_len_var = float(np.var(all_lengths, ddof=1)) if len(all_lengths) > 1 else 0.0

        # Java: (double)(backward.size() / forward.size()) -- integer division.
        down_up_ratio = (
            float(total_bwd_packets // total_fwd_packets) if total_fwd_packets else 0.0
        )
        avg_pkt_size = float(all_lengths.mean()) if len(all_lengths) else 0.0
        avg_fwd_segment_size = fwd_pkt_mean
        avg_bwd_segment_size = bwd_pkt_mean

        # CICIDS2017 raw data encodes "no window observed" as -1 (14.6% of training rows).
        init_win_fwd = float(flow['fwd_win']) if flow['fwd_win'] is not None else -1.0
        init_win_bwd = float(flow['bwd_win']) if flow['bwd_win'] is not None else -1.0
        
        # First forward packet excluded; subsequent forward packets with payload counted.
        act_data_pkt_fwd = float(sum(1 for p in fwd_pkts[1:] if p.plen >= 1))
        min_seg_size_fwd = float(min((p.hlen for p in fwd_pkts), default=0))

        # --- CICFlowMeter subflow statistics ---------------------------------
        # Training data: Subflow == Total on 100% of 225,745 rows (verified
        # 2026-10-01 against Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv).
        subflow_fwd_packets = total_fwd_packets
        subflow_fwd_bytes = total_len_fwd
        subflow_bwd_packets = total_bwd_packets
        subflow_bwd_bytes = total_len_bwd

        # --- CICFlowMeter bulk statistics ------------------------------------
        # Mirror BasicFlow.updateForwardBulk/updateBackwardBulk: only payload packets
        # participate; a >1s gap starts a new candidate; a bulk is recognized on its
        # 4th payload packet and subsequent packets extend it.
        fbulk_state_count = fbulk_packet_count = fbulk_size_total = fbulk_duration = 0
        bbulk_state_count = bbulk_packet_count = bbulk_size_total = bbulk_duration = 0

        fhelper_start = None
        fhelper_count = 0
        fhelper_size = 0

        bhelper_start = None
        bhelper_count = 0
        bhelper_size = 0

        last_f_bulk_ts = 0
        last_b_bulk_ts = 0

        for p in entries:
            size = p.plen
            if size <= 0:
                continue
            is_fwd = p.fwd
            ts_us = int(round(p.ts * 1_000_000.0))

            if is_fwd:
                # Opposite-direction bulk timestamp cancels a pending candidate.
                if fhelper_start is not None and last_b_bulk_ts > fhelper_start:
                    fhelper_start = None

                if fhelper_start is None:
                    fhelper_start = ts_us
                    last_f_bulk_ts = ts_us
                    fhelper_count = 1
                    fhelper_size = size
                elif (ts_us - last_f_bulk_ts) > self.CICFLOWMETER_ACTIVITY_TIMEOUT_US:
                    fhelper_start = ts_us
                    last_f_bulk_ts = ts_us
                    fhelper_count = 1
                    fhelper_size = size
                else:
                    fhelper_count += 1
                    fhelper_size += size
                    if fhelper_count == 4:
                        fbulk_state_count += 1
                        fbulk_packet_count += fhelper_count
                        fbulk_size_total += fhelper_size
                        fbulk_duration += ts_us - fhelper_start
                    elif fhelper_count > 4:
                        fbulk_packet_count += 1
                        fbulk_size_total += size
                        fbulk_duration += ts_us - last_f_bulk_ts
                    last_f_bulk_ts = ts_us
            else:
                if bhelper_start is not None and last_f_bulk_ts > bhelper_start:
                    bhelper_start = None

                if bhelper_start is None:
                    bhelper_start = ts_us
                    last_b_bulk_ts = ts_us
                    bhelper_count = 1
                    bhelper_size = size
                elif (ts_us - last_b_bulk_ts) > self.CICFLOWMETER_ACTIVITY_TIMEOUT_US:
                    bhelper_start = ts_us
                    last_b_bulk_ts = ts_us
                    bhelper_count = 1
                    bhelper_size = size
                else:
                    bhelper_count += 1
                    bhelper_size += size
                    if bhelper_count == 4:
                        bbulk_state_count += 1
                        bbulk_packet_count += bhelper_count
                        bbulk_size_total += bhelper_size
                        bbulk_duration += ts_us - bhelper_start
                    elif bhelper_count > 4:
                        bbulk_packet_count += 1
                        bbulk_size_total += size
                        bbulk_duration += ts_us - last_b_bulk_ts
                    last_b_bulk_ts = ts_us

        fwd_avg_bytes_bulk = (fbulk_size_total // fbulk_state_count) if fbulk_state_count else 0
        fwd_avg_packets_bulk = (fbulk_packet_count // fbulk_state_count) if fbulk_state_count else 0
        fwd_avg_bulk_rate = int(fbulk_size_total / (fbulk_duration / 1_000_000.0)) if fbulk_duration else 0
        bwd_avg_bytes_bulk = (bbulk_size_total // bbulk_state_count) if bbulk_state_count else 0
        bwd_avg_packets_bulk = (bbulk_packet_count // bbulk_state_count) if bbulk_state_count else 0
        bwd_avg_bulk_rate = int(bbulk_size_total / (bbulk_duration / 1_000_000.0)) if bbulk_duration else 0

        # --- CICFlowMeter active/idle statistics ------------------------------
        active_intervals = []
        idle_intervals = []
        start_active = end_active = int(round(all_pkts[0].ts * 1_000_000.0))
        for p in all_pkts[1:]:
            ts_us = int(round(p.ts * 1_000_000.0))
            if (ts_us - end_active) > self.CICFLOWMETER_ACTIVE_IDLE_TIMEOUT_US:
                if (end_active - start_active) > 0:
                    active_intervals.append(end_active - start_active)
                idle_intervals.append(ts_us - end_active)
                start_active = end_active = ts_us
            else:
                end_active = ts_us
        # The trailing active period only counts once the flow has had an idle gap. In all
        # 225,745 rows of the CICIDS2017 Friday CSV, Active > 0 occurs only together with
        # Idle > 0 (100%); emitting it for gap-free flows put 48 ms Active values on CIC DDoS
        # flows whose training rows say 0 (pcap replay, 2 Oct 2026).
        if idle_intervals and (end_active - start_active) > 0:
            active_intervals.append(end_active - start_active)

        def _summary(values):
            if not values:
                return 0.0, 0.0, 0.0, 0.0
            a = np.asarray(values, dtype=np.float64)
            return float(a.mean()), _sample_std(a), float(a.max()), float(a.min())

        active_mean, active_std, active_max, active_min = _summary(active_intervals)
        idle_mean, idle_std, idle_max, idle_min = _summary(idle_intervals)

        dst_port = flow['init_dport']

        features = np.array([
            dst_port, flow_duration_us,
            total_fwd_packets, total_bwd_packets,
            total_len_fwd, total_len_bwd,
            fwd_pkt_max, fwd_pkt_min, fwd_pkt_mean, fwd_pkt_std,
            bwd_pkt_max, bwd_pkt_min, bwd_pkt_mean, bwd_pkt_std,
            flow_bytes_per_s, flow_packets_per_s,
            flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
            fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
            bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
            float(fwd_flags['psh']), float(bwd_flags['psh']),
            float(fwd_flags['urg']), float(bwd_flags['urg']),
            fwd_header_len, bwd_header_len,
            fwd_packets_per_s, bwd_packets_per_s,
            min_pkt_len, max_pkt_len, pkt_len_mean, pkt_len_std, pkt_len_var,
            float(all_flags['fin']), float(all_flags['syn']), float(all_flags['rst']),
            float(all_flags['psh']), float(all_flags['ack']), float(all_flags['urg']),
            float(all_flags['cwe']), float(all_flags['ece']),
            down_up_ratio, avg_pkt_size, avg_fwd_segment_size, avg_bwd_segment_size,
            fwd_header_len,
            fwd_avg_bytes_bulk, fwd_avg_packets_bulk, fwd_avg_bulk_rate,
            bwd_avg_bytes_bulk, bwd_avg_packets_bulk, bwd_avg_bulk_rate,
            subflow_fwd_packets, subflow_fwd_bytes, subflow_bwd_packets, subflow_bwd_bytes,
            init_win_fwd, init_win_bwd, act_data_pkt_fwd, min_seg_size_fwd,
            active_mean, active_std, active_max, active_min,
            idle_mean, idle_std, idle_max, idle_min,
        ], dtype=np.float32)

        if features.shape != (78,):
            raise RuntimeError(f"CICFlowMeter feature vector has wrong shape: {features.shape}")
        return features

    # ------------------------------------------------------------------ fusion / alerting

    def _note_new_flow(self, src, ts):
        """Record a new connection from `src` at packet time `ts` (seconds)."""
        if not hasattr(self, "_src_flow_times"):
            self._src_flow_times = {}
        q = self._src_flow_times.setdefault(src, deque())
        q.append(ts)
        cutoff = ts - self.RATE_WINDOW_S
        while q and q[0] < cutoff:
            q.popleft()
        if len(self._src_flow_times) > 50000:              # bound memory: drop idle sources
            self._src_flow_times = {k: v for k, v in self._src_flow_times.items()
                                    if v and v[-1] >= cutoff}

    def _source_rate(self, src, now_ts):
        """New connections per second from `src` over the last RATE_WINDOW_S seconds."""
        q = getattr(self, "_src_flow_times", {}).get(src)
        if not q:
            return 0.0
        cutoff = now_ts - self.RATE_WINDOW_S
        return sum(1 for t in q if t >= cutoff) / self.RATE_WINDOW_S

    def _process_prediction(self, flow_key, recon_error: float,
                            rf_attack_prob: float = None,
                            threat_name: str = None):
        """
        ae_score = e / (e + recon_threshold): 0.5 at the benign-calibrated threshold.

        FUSION — confidence-override. With the RF available, the baseline is the
        0.5/0.5 average of ae_score and RF P(attack). A single confident model overrides:
          * rf_attack_prob > RF_OVERRIDE_CONF -> KNOWN attack (checked first).
          * ae_score > AE_OVERRIDE_CONF -> possible NOVEL attack.
        An override is only labelled when the resulting score crosses the alert cutoff.
        """
        if rf_attack_prob is None and not self.ae_only_alerting_validated:
            self._ae_only_suppressed += 1
            if self._ae_only_suppressed == 1 or self._ae_only_suppressed % 1000 == 0:
                logger.warning(
                    f"Suppressing AE-only results ({self._ae_only_suppressed} so far): live score "
                    "variance has not been validated (set IDS_AE_ONLY_ALERTING_VALIDATED=true "
                    "only after live-lab validation)."
                )
            return

        ae_score = recon_error / (recon_error + self.recon_threshold)

        flow = self.flow_tracker[flow_key]
        # Stored initiator, NOT flow_key[0][0] (flow_key is sorted).
        src_ip = flow['init_src']
        settings = self._load_settings()

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
            if rf_attack_prob > self.RF_OVERRIDE_CONF:
                override_reason = 'random forest override (known attack pattern)'
                anomaly_score = max(fused_score, rf_attack_prob)
            elif ae_score > self.AE_OVERRIDE_CONF:
                override_reason = 'autoencoder override (possible novel attack)'
                anomaly_score = max(fused_score, ae_score)
            if override_reason and anomaly_score <= alert_cutoff:
                override_reason = None   # did not alert -> do not claim it did
            # "low" sensitivity means fewer alerts: the moderate-confidence path is off there.
            if (override_reason is None and anomaly_score <= alert_cutoff
                    and rf_attack_prob > self.RF_ALERT_CONF
                    and settings.get("sensitivity", "medium") != "low"):
                override_reason = 'random forest (moderate confidence)'
                anomaly_score = max(fused_score, rf_attack_prob)
        else:
            fused_score = ae_score
            anomaly_score = ae_score

        if flow['packets'] >= 2:
            rf_str = 'n/a' if rf_attack_prob is None else f"{rf_attack_prob:.4f}"
            ovr_str = f" OVERRIDE[{override_reason}]" if override_reason else ""
            logger.info(
                f"DIAGNOSTIC recon_error={recon_error:.6f} threshold={self.recon_threshold:.6f} "
                f"(calibrated={self._threshold_calibrated}) ae_score={ae_score:.4f} rf_prob={rf_str} "
                f"fused={fused_score:.4f} anomaly_score={anomaly_score:.4f}{ovr_str} "
                f"packets={flow['packets']} bytes={flow['bytes']} src={src_ip}"
            )

        rf_moderate = override_reason == 'random forest (moderate confidence)'
        alerting = anomaly_score > alert_cutoff or rf_moderate

        # Rate context (see RATE_* constants). Packet time, so replay and live agree.
        src_rate = self._source_rate(src_ip, flow['last_seen'].timestamp())
        ae_led = bool(override_reason and override_reason.startswith('autoencoder override'))
        rf_driven = rf_attack_prob is not None and rf_attack_prob > 0.5 and not ae_led
        # The gate encodes "a flood needs a high connection rate". It applies to binary RFs (their
        # one attack class is a flood here) and to flood classes of a multi-class RF; slow attack
        # classes such as Brute Force or Bot are not rate-gated (multiday_v1, 3 Oct 2026).
        rate_gated_class = (not getattr(self, "_rf_multiclass", False)) or threat_name in self.RATE_GATED_CLASSES
        if alerting and rf_driven and rate_gated_class and src_rate < self.RF_MIN_SRC_RATE:
            # The RF names a flood/DDoS pattern, but this source is not flooding.
            self._rate_gated = getattr(self, "_rate_gated", 0) + 1
            alerting = False
        rate_flood = (not alerting) and src_rate >= self.RATE_FLOOD_CONN_PER_S
        if rate_flood:
            override_reason = 'connection-rate flood'

        if alerting or rate_flood:
            severity = self._compute_severity(anomaly_score, settings)
            if ae_led:
                severity = self.AE_OVERRIDE_MAX_SEVERITY
            if rf_moderate:
                severity = self.RF_MODERATE_SEVERITY
            if rate_flood:
                severity = self.RATE_FLOOD_SEVERITY

            # Cooldown per (source, severity), not per port (port scans rotate ports).
            k = (src_ip, severity)
            now = time.time()
            last, suppressed = self._last_alert.get(k, (0.0, 0))
            if now - last < self.alert_cooldown:
                self._last_alert[k] = (last, suppressed + 1)
                return
            self._last_alert[k] = (now, 0)
            if len(self._last_alert) > 10000:
                self._last_alert = {a: v for a, v in self._last_alert.items()
                                    if v[0] > now - self.alert_cooldown}

            alert_payload = {
                'timestamp': int(time.time()),
                'flow_key': src_ip,
                'anomaly_score': anomaly_score,
                'ae_anomaly_score': ae_score,
                'rf_attack_prob': rf_attack_prob,
                'fused_score': fused_score,
                'detection_source': (
                    override_reason if override_reason
                    else 'ensemble (autoencoder + random forest)'
                    if rf_attack_prob is not None else 'autoencoder only'
                ),
                # An AE-led alert must not borrow the RF's attack name (live test 2 Oct 2026:
                # a normal download alerted by the AE was labelled "TCP Connect Flood").
                'threat_type': threat_name if threat_name and threat_name != 'Benign' and not ae_led
                               else 'Connection Flood (rate)' if rate_flood
                               else 'Network Anomaly',
                # New connections/s from this source over RATE_WINDOW_S at scoring time.
                'src_conn_rate': round(src_rate, 1),
                'severity': severity,
                'src_ip': src_ip,
                'dst_ip': flow.get('init_dst', flow_key[1][0]),
                # Port of the initiator's destination (the service hit): makes an alert
                # attributable without a packet capture (e.g. :8080 flood vs WSL control traffic).
                'dst_port': flow.get('init_dport'),
                'protocol': 'TCP' if flow['protocol'] == 6 else 'UDP',
                'packet_count': flow['packets'],
                'bytes_transferred': flow['bytes'],
                'flow_duration': (flow['last_seen'] - flow['first_seen']).total_seconds(),
                'feature_coverage': self._live_feature_coverage(),
                'unsupported_live_features': list(self.UNSUPPORTED_LIVE_FEATURES),
                'evidence_origin': getattr(self, 'evidence_origin', 'live_unclassified'),
                'suppressed_since_last': suppressed,
            }

            try:
                alert_payload.update(save_threat_evidence(alert_payload))
            except Exception as e:
                logger.warning(f"Could not save threat evidence snapshot: {e}")

            if self.redis_client:
                try:
                    self.redis_client.xadd(
                        'ids:alerts', {'data': json.dumps(alert_payload)},
                        maxlen=5000, approximate=True,
                    )
                except Exception as e:
                    logger.warning(f"Redis failed: {e}")

            # AutoBlock: opt-in via Settings (default OFF).
            if settings.get('autoBlock', False) and severity == 'CRITICAL' and self._should_block(flow):
                self._block(src_ip)

    # ------------------------------------------------------------------ IPS guardrails

    def _should_block(self, flow) -> bool:
        """
        Permit AutoBlock only for an inbound TCP flow to one of this host's IPs whose
        initiator COMPLETED a handshake (bare SYN, our SYN-ACK, forward ACK of
        synack_seq + 1). SYN floods are never auto-blocked; use SYN cookies.
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

    def _load_autoblock_state(self):
        """Restore non-expired IDS blocks and reconcile against the actual firewall."""
        now = time.time()
        try:
            with open(self._autoblock_state_path, encoding="utf-8") as f:
                raw = json.load(f)
            self._blocked = {
                str(ip): float(until)
                for ip, until in raw.items()
                if float(until) > now and ipaddress.ip_address(ip).is_global
            }
        except FileNotFoundError:
            self._blocked = {}
        except Exception as e:
            logger.warning(f"[IPS] Could not load AutoBlock state: {e}; starting with no tracked blocks")
            self._blocked = {}

        system = platform.system().lower()
        if system == "linux":
            try:
                out = _fw(["iptables", "-S", "INPUT"])
                present = set()
                if out.returncode == 0:
                    for line in out.stdout.decode(errors="replace").splitlines():
                        if IDS_IPTABLES_COMMENT not in line or " -j DROP" not in line:
                            continue
                        parts = line.split()
                        if "-s" not in parts:
                            continue
                        # iptables -S prints "-s 203.0.113.7/32"; strip the prefix length.
                        ip = parts[parts.index("-s") + 1].split("/", 1)[0]
                        present.add(ip)
                        if ip not in self._blocked:
                            unblock_ip(ip)
                for ip in list(self._blocked):
                    if ip not in present:
                        self._blocked.pop(ip, None)
            except Exception as e:
                logger.warning(f"[IPS] Could not reconcile Linux firewall rules: {e}")
        elif system == "windows":
            for ip in list(self._blocked):
                try:
                    name = f"Block_IDS_{ip}"
                    result = _fw(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"])
                    if result.returncode != 0:
                        self._blocked.pop(ip, None)
                except Exception as e:
                    logger.warning(f"[IPS] Could not reconcile Windows rule for {ip}: {e}")

        self._persist_autoblock_state()

    def _persist_autoblock_state(self):
        try:
            path = os.path.abspath(self._autoblock_state_path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._blocked, f, indent=2, sort_keys=True)
            os.replace(tmp, path)
        except Exception as e:
            logger.warning(f"[IPS] Could not persist AutoBlock state: {e}")

    def _block(self, ip):
        if block_ip(ip):
            self._blocked[ip] = time.time() + self.block_ttl
            self._persist_autoblock_state()

    def _expire_blocks(self):
        now = time.time()
        changed = False
        for ip in [ip for ip, until in self._blocked.items() if until <= now]:
            unblock_ip(ip)
            self._blocked.pop(ip, None)
            changed = True
        if changed:
            self._persist_autoblock_state()

    def release_blocks(self):
        """Remove every IDS-owned rule this process tracks (called on clean shutdown)."""
        for ip in list(self._blocked):
            unblock_ip(ip)
            self._blocked.pop(ip, None)
        self._persist_autoblock_state()

    def _compute_severity(self, anomaly_score: float, settings: dict = None) -> str:
        """Severity bands from the Settings page thresholds (defaults 0.95 / 0.85)."""
        settings = settings or {}
        critical_threshold = settings.get('criticalThreshold', 0.95)
        high_threshold = settings.get('highThreshold', 0.85)
        if anomaly_score > critical_threshold:
            return 'CRITICAL'
        elif anomaly_score > high_threshold:
            return 'HIGH'
        else:
            return 'MEDIUM'

    @staticmethod
    def _capture_filter(local_ips=None) -> str:
        """
        BPF filter excluding the sensor's own plumbing (REDIS_PORT, PORT,
        IDS_EXCLUDE_PORTS) only where one end is this host. Remaining blind spot:
        external traffic TO those local ports; keep them bound to loopback.
        """
        ports = {int(os.environ.get("REDIS_PORT", "6379")), int(os.environ.get("PORT", "5000"))}
        for p in os.environ.get("IDS_EXCLUDE_PORTS", "").split(","):
            if p.strip().isdigit():
                ports.add(int(p.strip()))
        ips = sorted(local_ips if local_ips is not None else _local_ips())
        if not ips:
            logger.warning("Could not determine local IPs; excluding plumbing ports on ALL hosts "
                           "(attacks on those ports elsewhere will be invisible).")
            return "(tcp or udp)" + "".join(f" and not port {p}" for p in sorted(ports))
        hosts = " or ".join(f"host {ip}" for ip in ips)
        return "(tcp or udp)" + "".join(f" and not (port {p} and ({hosts}))" for p in sorted(ports))

    def start_capture(self, interface: str = 'eth0', packet_count: int = 0):
        bpf = self._capture_filter()
        logger.info(f"Starting packet capture on {interface} (filter: {bpf})")
        self._stop.clear()
        if self._queue is None:
            self._queue = queue.Queue(maxsize=int(os.environ.get("IDS_QUEUE_MAX", "50000")))
        self._worker_thread = threading.Thread(target=self._worker, daemon=True,
                                               name="ids-scoring-worker")
        self._worker_thread.start()
        threading.Thread(target=self._ticker, daemon=True, name="ids-health-ticker").start()
        threading.Thread(target=self._capture_heartbeat, daemon=True, name="ids-capture-heartbeat").start()
        iface = interface if interface and interface != 'auto' else None
        try:
            if packet_count > 0:
                sniff(iface=iface, prn=self.packet_callback, store=False,
                      count=packet_count, filter=bpf)
            # One long-lived capture session. The old loop (sniff(timeout=10), reopen) closed
            # the Npcap handle every 10 s and dropped packets in each gap; on the 1 Oct 2026
            # WSL flood run only ~25% of connections were seen. Reopen only if the session dies.
            quick_failures = 0
            while packet_count == 0 and not self._stop.is_set():
                sniffer = AsyncSniffer(iface=iface, prn=self.packet_callback,
                                       store=False, filter=bpf)
                started = time.monotonic()
                sniffer.start()
                while sniffer.running and not self._stop.is_set():
                    self._stop.wait(1.0)
                if sniffer.running:
                    sniffer.stop()
                    break
                if self._stop.is_set():
                    break
                # AsyncSniffer (scapy 2.5) swallows errors raised in its thread, so a session
                # that dies at once (no privileges, bad interface, Npcap down) would otherwise
                # reopen forever. Fail loudly instead.
                quick_failures = quick_failures + 1 if time.monotonic() - started < 5 else 0
                if quick_failures >= 3:
                    raise RuntimeError(
                        f"Capture on '{interface}' failed to start 3 times in a row. Check "
                        "Administrator rights, Npcap, and the interface name.")
                logger.warning("Scapy capture session ended unexpectedly; reopening interface '%s'.",
                               interface)
                self._stop.wait(1.0)
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            raise
        finally:
            self._stop.set()
            if self._worker_thread is not None:
                self._worker_thread.join(timeout=5)
            # Drain what the worker didn't reach, then score everything still open.
            try:
                while True:
                    self._process_summary(self._queue.get_nowait())
            except queue.Empty:
                pass
            except Exception as e:
                logger.error(f"Shutdown drain error: {e}", exc_info=True)
            try:
                with self._lock:
                    self._last_sweep_at = 0.0
                    self._inference_batch()
            except Exception as e:
                logger.error(f"Shutdown flush error: {e}", exc_info=True)
            self.release_blocks()