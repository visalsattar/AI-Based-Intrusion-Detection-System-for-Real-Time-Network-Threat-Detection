# backend/src/ids_pipeline.py
import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, Tuple
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from redis import Redis
import subprocess
import json
import time

# Setting up logging for real-time monitoring[cite: 4]
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import platform

def block_ip(ip):
    """
    Automated IPS functionality to block malicious IPs at the OS level.
    Uses iptables on Linux (the real deploy target — see backend/Dockerfile,
    which is python:3.11-slim) and falls back to the Windows Firewall command
    when running directly on Windows during local development/demos.
    """
    system = platform.system().lower()
    try:
        if system == "linux":
            # -C (check) first so re-running doesn't pile up duplicate rules
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            if check.returncode != 0:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logger.warning(f"!!! [IPS] Blocked malicious IP via iptables: {ip}")
        elif system == "windows":
            rule_name = f"Block_IDS_{ip}"
            cmd = (f'netsh advfirewall firewall add rule name="{rule_name}" '
                   f'dir=in action=block remoteip={ip}')
            os.system(cmd)
            logger.warning(f"!!! [IPS] Blocked malicious IP via Windows Firewall: {ip}")
        else:
            logger.warning(f"[IPS] Automatic blocking not implemented for platform '{system}' — "
                            f"IP {ip} was flagged CRITICAL but NOT blocked.")
    except subprocess.CalledProcessError as e:
        logger.error(f"[IPS] Failed to block {ip} (likely missing NET_ADMIN capability "
                      f"in this container — add --cap-add=NET_ADMIN): {e}")
    except Exception as e:
        logger.error(f"[IPS] Unexpected error blocking {ip}: {e}")
    
class RealTimeIDSPipeline:
    """
    Orchestrates real-time packet capture → feature extraction → AI inference → alerting[cite: 4].
    """
    
    def __init__(self, 
                 model_path: str,
                 feature_extractor_path: str,
                 alert_threshold: float = 0.75, 
                 packet_batch_size: int = 100):
        self.model_path = model_path
        self.alert_threshold = alert_threshold
        self.packet_batch_size = packet_batch_size
        
        try:
            # Redis connection logic for alert persistence[cite: 4]
            redis_host = os.environ.get('REDIS_HOST', 'redis')
            self.redis_client = Redis(host=redis_host, port=6379, decode_responses=True)
            self.redis_client.ping()
            logger.info(f"Redis connected successfully (host={redis_host})")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Alerts won't be persisted.")
            self.redis_client = None
        
        try:
            # Loading AI models for anomaly detection[cite: 4]
            import tensorflow as tf
            from joblib import load
            
            self.ensemble_model = tf.keras.models.load_model(model_path, compile=False)
            self.feature_scaler = load(feature_extractor_path)
            logger.info("Models loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            raise

        # The autoencoder's raw output is a *reconstructed feature vector*,
        # not a scalar score — "anomalous" means "poorly reconstructed", so
        # the real signal is reconstruction error (MSE between input and
        # output), benchmarked against a threshold calibrated on real benign
        # data (see model_evaluation.py::evaluate_autoencoder, which writes
        # this value to models/real_metrics.json). Without that calibration
        # file, detection still runs but with an explicitly uncalibrated
        # fallback — logged loudly rather than silently guessed.
        self.recon_threshold, self._threshold_calibrated = self._load_recon_threshold(model_path)

        self.packet_buffer = []
        self.flow_tracker = {}
        self._settings_cache = {}
        self._settings_loaded_at = 0.0

    @staticmethod
    def _load_recon_threshold(model_path: str):
        """
        Reads the real benign-data-derived reconstruction-error threshold
        produced by `python src/model_evaluation.py <preprocessed_csv>`.
        Returns (threshold, is_calibrated).
        """
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
            f"meaningless until you run `python src/model_evaluation.py <preprocessed_csv>` "
            f"to generate real_metrics.json from your real training data."
        )
        return fallback, False

    def _load_settings(self) -> dict:
        """
        Re-reads the Settings page's saved config (POST /api/save-settings)
        from Redis at most once every 5 seconds, so adjusting the Critical/
        High thresholds or the Automatic IP Blocking toggle in the UI takes
        effect on the next batch of packets without restarting capture.
        """
        now = time.time()
        if self.redis_client and (now - self._settings_loaded_at) > 5:
            try:
                stored = self.redis_client.get('ids:settings')
                if stored:
                    self._settings_cache = json.loads(stored)
            except Exception as e:
                logger.debug(f"Could not refresh live settings: {e}")
            self._settings_loaded_at = now
        return self._settings_cache
        
    def packet_callback(self, packet):
        """Scapy callback for each captured packet[cite: 4]."""
        if not (IP in packet):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            return
        
        flow_key = tuple(sorted([
            (src_ip, src_port),
            (dst_ip, dst_port)
        ])) + (protocol,)
        
        if flow_key not in self.flow_tracker:
            self.flow_tracker[flow_key] = {
                'packets': 0,
                'bytes': 0,
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'protocol': protocol,
                'packet_list': [],
                # The first packet observed for this flow defines "forward".
                # CICIDS2017's Fwd/Bwd split features are meaningless without
                # this -- every packet from here on is tagged against it.
                'init_src': src_ip,
                'init_sport': src_port,
                'init_dst': dst_ip,
                'init_dport': dst_port,
                'fwd_win': None,
                'bwd_win': None,
            }
        
        flow = self.flow_tracker[flow_key]
        flow['packets'] += 1
        flow['bytes'] += len(packet)
        flow['last_seen'] = datetime.now()

        is_forward = (src_ip == flow['init_src'] and src_port == flow['init_sport'])
        if TCP in packet:
            win = int(packet[TCP].window)
            if is_forward and flow['fwd_win'] is None:
                flow['fwd_win'] = win
            elif not is_forward and flow['bwd_win'] is None:
                flow['bwd_win'] = win

        flow['packet_list'].append((packet, is_forward))
        
        self.packet_buffer.append((flow_key, packet))
        
        if len(self.packet_buffer) >= self.packet_batch_size:
            self._inference_batch()
    
    def _inference_batch(self):
        """Batch inference for anomaly detection[cite: 4]."""
        batch = self.packet_buffer.copy()
        
        logger.info(f"AI Analyzing batch of {len(batch)} live network packets...")
        
        self.packet_buffer.clear()
        
        if not batch:
            return
        
        try:
            features_batch = []
            flow_keys_batch = []
            
            for flow_key, packet in batch:
                features = self._extract_flow_features(flow_key)
                if features is not None:
                    features_batch.append(features)
                    flow_keys_batch.append(flow_key)
            
            if not features_batch:
                return
            
            features_array = np.array(features_batch)
            features_normalized = self.feature_scaler.transform(features_array)
            
            reconstructed = self.ensemble_model.predict(
                features_normalized,
                batch_size=len(features_normalized),
                verbose=0
            )

            # Real anomaly signal: per-sample reconstruction error (MSE
            # between the scaled input and the autoencoder's reconstruction
            # of it). A poorly-reconstructed flow looks unlike anything the
            # model saw during training on benign traffic.
            recon_errors = np.mean(np.square(features_normalized - reconstructed), axis=1)

            for flow_key, recon_error in zip(flow_keys_batch, recon_errors):
                self._process_prediction(flow_key, float(recon_error))
                
        except Exception as e:
            logger.error(f"Inference batch error: {e}")
    
    def _extract_flow_features(self, flow_key: Tuple) -> np.ndarray:
        """
        Extract a real, correctly-ordered 78-feature CICIDS2017-compatible
        vector from a live flow.

        Column order matches feature_scaler.pkl's feature_names_in_ exactly
        (verified against the fitted scaler at
        backend/models/feature_scaler.pkl). Earlier versions of this method
        computed ~24 generic stats and zero-padded the remaining 54 slots,
        which silently misaligned every value with the wrong column and
        guaranteed near-maximum reconstruction error on every flow,
        regardless of whether the traffic was actually anomalous. That bug
        is why live detections previously showed 100% anomaly score on
        every single flow.

        A handful of CICIDS2017 columns (Fwd/Bwd Avg Bulk Rate, Active/Idle
        Mean/Std/Max/Min) require multi-flow bulk/idle-gap analysis that
        isn't tracked by this lightweight per-flow buffer; those are left
        at 0, which mirrors how CICIDS2017 itself encodes "not applicable"
        for short flows. Everything else is computed directly from the
        real captured packets.
        """
        if flow_key not in self.flow_tracker:
            return None

        flow = self.flow_tracker[flow_key]
        entries = flow['packet_list']
        if not entries:
            return None

        fwd_pkts = [p for p, is_fwd in entries if is_fwd]
        bwd_pkts = [p for p, is_fwd in entries if not is_fwd]

        flow_duration_s = (flow['last_seen'] - flow['first_seen']).total_seconds()
        flow_duration = flow_duration_s if flow_duration_s > 0 else 0.001
        flow_duration_us = flow_duration * 1_000_000

        total_fwd_packets = len(fwd_pkts)
        total_bwd_packets = len(bwd_pkts)

        fwd_lengths = np.array([len(p) for p in fwd_pkts], dtype=np.float64)
        bwd_lengths = np.array([len(p) for p in bwd_pkts], dtype=np.float64)
        all_lengths = np.array([len(p) for p, _ in entries], dtype=np.float64)

        total_len_fwd = float(fwd_lengths.sum()) if len(fwd_lengths) else 0.0
        total_len_bwd = float(bwd_lengths.sum()) if len(bwd_lengths) else 0.0

        fwd_pkt_max = float(fwd_lengths.max()) if len(fwd_lengths) else 0.0
        fwd_pkt_min = float(fwd_lengths.min()) if len(fwd_lengths) else 0.0
        fwd_pkt_mean = float(fwd_lengths.mean()) if len(fwd_lengths) else 0.0
        fwd_pkt_std = float(fwd_lengths.std()) if len(fwd_lengths) > 1 else 0.0

        bwd_pkt_max = float(bwd_lengths.max()) if len(bwd_lengths) else 0.0
        bwd_pkt_min = float(bwd_lengths.min()) if len(bwd_lengths) else 0.0
        bwd_pkt_mean = float(bwd_lengths.mean()) if len(bwd_lengths) else 0.0
        bwd_pkt_std = float(bwd_lengths.std()) if len(bwd_lengths) > 1 else 0.0

        total_bytes = flow['bytes']
        num_packets = flow['packets']
        flow_bytes_per_s = total_bytes / flow_duration if flow_duration > 0 else 0.0
        flow_packets_per_s = num_packets / flow_duration if flow_duration > 0 else 0.0
        fwd_packets_per_s = total_fwd_packets / flow_duration if flow_duration > 0 else 0.0
        bwd_packets_per_s = total_bwd_packets / flow_duration if flow_duration > 0 else 0.0

        def _iat_stats(pkts):
            if len(pkts) < 2:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            times = np.array([float(p.time) for p in pkts], dtype=np.float64)
            times.sort()
            iat = np.diff(times) * 1_000_000  # microseconds
            return float(iat.sum()), float(iat.mean()), \
                   (float(iat.std()) if len(iat) > 1 else 0.0), \
                   float(iat.max()), float(iat.min())

        all_pkts_only = [p for p, _ in entries]
        _, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(all_pkts_only)
        fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(fwd_pkts)
        bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(bwd_pkts)

        def _flag_counts(pkts):
            c = dict(fin=0, syn=0, rst=0, psh=0, ack=0, urg=0, cwe=0, ece=0)
            for p in pkts:
                if TCP in p:
                    f = p[TCP].flags
                    c['fin'] += int(f.F)
                    c['syn'] += int(f.S)
                    c['rst'] += int(f.R)
                    c['psh'] += int(f.P)
                    c['ack'] += int(f.A)
                    c['urg'] += int(f.U)
                    c['cwe'] += int(getattr(f, 'C', 0) or 0)
                    c['ece'] += int(getattr(f, 'E', 0) or 0)
            return c

        fwd_flags = _flag_counts(fwd_pkts)
        bwd_flags = _flag_counts(bwd_pkts)
        all_flags = _flag_counts(all_pkts_only)

        def _ip_header_len(p):
            # IP header length (4-byte words -> bytes) + TCP/UDP header length
            ihl_bytes = int(p[IP].ihl) * 4 if hasattr(p[IP], 'ihl') and p[IP].ihl else 20
            if TCP in p:
                data_offset = int(p[TCP].dataofs) * 4 if p[TCP].dataofs else 20
                return ihl_bytes + data_offset
            if UDP in p:
                return ihl_bytes + 8
            return ihl_bytes

        fwd_header_len = float(sum(_ip_header_len(p) for p in fwd_pkts))
        bwd_header_len = float(sum(_ip_header_len(p) for p in bwd_pkts))

        min_pkt_len = float(all_lengths.min()) if len(all_lengths) else 0.0
        max_pkt_len = float(all_lengths.max()) if len(all_lengths) else 0.0
        pkt_len_mean = float(all_lengths.mean()) if len(all_lengths) else 0.0
        pkt_len_std = float(all_lengths.std()) if len(all_lengths) > 1 else 0.0
        pkt_len_var = float(all_lengths.var()) if len(all_lengths) > 1 else 0.0

        down_up_ratio = (total_bwd_packets / total_fwd_packets) if total_fwd_packets > 0 else 0.0
        avg_pkt_size = float(all_lengths.mean()) if len(all_lengths) else 0.0
        avg_fwd_segment_size = fwd_pkt_mean
        avg_bwd_segment_size = bwd_pkt_mean

        init_win_fwd = float(flow['fwd_win']) if flow['fwd_win'] is not None else -1.0
        init_win_bwd = float(flow['bwd_win']) if flow['bwd_win'] is not None else -1.0
        act_data_pkt_fwd = float(sum(1 for p in fwd_pkts if len(p) > _ip_header_len(p)))
        min_seg_size_fwd = float(min((_ip_header_len(p) for p in fwd_pkts), default=0))

        dst_port = flow['init_dport']

        # Ordered to exactly match feature_scaler.pkl's feature_names_in_
        features = np.array([
            dst_port,                          # 0  Destination Port
            flow_duration_us,                  # 1  Flow Duration
            total_fwd_packets,                 # 2  Total Fwd Packets
            total_bwd_packets,                 # 3  Total Backward Packets
            total_len_fwd,                     # 4  Total Length of Fwd Packets
            total_len_bwd,                     # 5  Total Length of Bwd Packets
            fwd_pkt_max,                       # 6  Fwd Packet Length Max
            fwd_pkt_min,                       # 7  Fwd Packet Length Min
            fwd_pkt_mean,                      # 8  Fwd Packet Length Mean
            fwd_pkt_std,                       # 9  Fwd Packet Length Std
            bwd_pkt_max,                       # 10 Bwd Packet Length Max
            bwd_pkt_min,                       # 11 Bwd Packet Length Min
            bwd_pkt_mean,                      # 12 Bwd Packet Length Mean
            bwd_pkt_std,                       # 13 Bwd Packet Length Std
            flow_bytes_per_s,                  # 14 Flow Bytes/s
            flow_packets_per_s,                # 15 Flow Packets/s
            flow_iat_mean,                     # 16 Flow IAT Mean
            flow_iat_std,                      # 17 Flow IAT Std
            flow_iat_max,                      # 18 Flow IAT Max
            flow_iat_min,                      # 19 Flow IAT Min
            fwd_iat_total,                     # 20 Fwd IAT Total
            fwd_iat_mean,                      # 21 Fwd IAT Mean
            fwd_iat_std,                       # 22 Fwd IAT Std
            fwd_iat_max,                       # 23 Fwd IAT Max
            fwd_iat_min,                       # 24 Fwd IAT Min
            bwd_iat_total,                     # 25 Bwd IAT Total
            bwd_iat_mean,                      # 26 Bwd IAT Mean
            bwd_iat_std,                       # 27 Bwd IAT Std
            bwd_iat_max,                       # 28 Bwd IAT Max
            bwd_iat_min,                       # 29 Bwd IAT Min
            float(fwd_flags['psh']),           # 30 Fwd PSH Flags
            float(bwd_flags['psh']),           # 31 Bwd PSH Flags
            float(fwd_flags['urg']),           # 32 Fwd URG Flags
            float(bwd_flags['urg']),           # 33 Bwd URG Flags
            fwd_header_len,                    # 34 Fwd Header Length
            bwd_header_len,                    # 35 Bwd Header Length
            fwd_packets_per_s,                 # 36 Fwd Packets/s
            bwd_packets_per_s,                 # 37 Bwd Packets/s
            min_pkt_len,                       # 38 Min Packet Length
            max_pkt_len,                       # 39 Max Packet Length
            pkt_len_mean,                      # 40 Packet Length Mean
            pkt_len_std,                       # 41 Packet Length Std
            pkt_len_var,                       # 42 Packet Length Variance
            float(all_flags['fin']),           # 43 FIN Flag Count
            float(all_flags['syn']),           # 44 SYN Flag Count
            float(all_flags['rst']),           # 45 RST Flag Count
            float(all_flags['psh']),           # 46 PSH Flag Count
            float(all_flags['ack']),           # 47 ACK Flag Count
            float(all_flags['urg']),           # 48 URG Flag Count
            float(all_flags['cwe']),           # 49 CWE Flag Count
            float(all_flags['ece']),           # 50 ECE Flag Count
            down_up_ratio,                     # 51 Down/Up Ratio
            avg_pkt_size,                      # 52 Average Packet Size
            avg_fwd_segment_size,              # 53 Avg Fwd Segment Size
            avg_bwd_segment_size,              # 54 Avg Bwd Segment Size
            fwd_header_len,                    # 55 Fwd Header Length.1 (CICIDS duplicates this column)
            0.0,                               # 56 Fwd Avg Bytes/Bulk (not tracked — short live flows)
            0.0,                               # 57 Fwd Avg Packets/Bulk
            0.0,                               # 58 Fwd Avg Bulk Rate
            0.0,                               # 59 Bwd Avg Bytes/Bulk
            0.0,                               # 60 Bwd Avg Packets/Bulk
            0.0,                               # 61 Bwd Avg Bulk Rate
            total_fwd_packets,                 # 62 Subflow Fwd Packets
            total_len_fwd,                     # 63 Subflow Fwd Bytes
            total_bwd_packets,                 # 64 Subflow Bwd Packets
            total_len_bwd,                     # 65 Subflow Bwd Bytes
            init_win_fwd,                      # 66 Init_Win_bytes_forward
            init_win_bwd,                      # 67 Init_Win_bytes_backward
            act_data_pkt_fwd,                  # 68 act_data_pkt_fwd
            min_seg_size_fwd,                  # 69 min_seg_size_forward
            0.0,                               # 70 Active Mean (not tracked)
            0.0,                               # 71 Active Std
            0.0,                               # 72 Active Max
            0.0,                               # 73 Active Min
            0.0,                               # 74 Idle Mean
            0.0,                               # 75 Idle Std
            0.0,                               # 76 Idle Max
            0.0,                               # 77 Idle Min
        ], dtype=np.float32)

        return features

    def _process_prediction(self, flow_key, recon_error: float):
        """
        Processes a real reconstruction-error value and triggers alerts/IPS.

        recon_error is the raw MSE between a flow's scaled features and the
        autoencoder's reconstruction of them — unbounded and scale-dependent.
        We convert it to a bounded (0,1) anomaly_score using the calibrated
        threshold (self.recon_threshold, the benign-data error level above
        which traffic is considered anomalous): score = e / (e + threshold).
        At exactly the threshold this gives 0.5; well below it tends to 0;
        well above it saturates toward 1 — and it stays compatible with the
        Settings page's 0-1 Critical/High sliders without needing to assume
        a fixed scale for raw MSE.
        """
        anomaly_score = recon_error / (recon_error + self.recon_threshold)
        flow = self.flow_tracker[flow_key]
        src_ip = flow_key[0][0]
        settings = self._load_settings()

        # Whitelist protection to prevent blocking the host or router
        whitelist = ['192.168.18.1', '192.168.18.12']

        if flow['packets'] >= 2:
            logger.info(
                f"DIAGNOSTIC recon_error={recon_error:.6f} threshold={self.recon_threshold:.6f} "
                f"(calibrated={self._threshold_calibrated}) anomaly_score={anomaly_score:.4f} "
                f"packets={flow['packets']} bytes={flow['bytes']} src={src_ip}"
            )

        if anomaly_score > self.alert_threshold:
            severity = self._compute_severity(anomaly_score, settings)
            
            alert_payload = {
                'timestamp': int(time.time()),
                'flow_key': src_ip,
                'anomaly_score': anomaly_score,
                'threat_type': 'Live Network Anomaly',
                'severity': severity,
                'src_ip': src_ip,
                'dst_ip': flow.get('init_dst', flow_key[1][0]),
                'protocol': 'TCP' if flow['protocol'] == 6 else 'UDP',
                'packet_count': flow['packets'],
                'bytes_transferred': flow['bytes'],
                'flow_duration': (flow['last_seen'] - flow['first_seen']).total_seconds()
            }
            
            if self.redis_client:
                try:
                    self.redis_client.xadd('ids:alerts', {'data': json.dumps(alert_payload)})
                except Exception as e:
                    logger.warning(f"Redis failed: {e}")

            # IPS Trigger: only auto-block if the operator has explicitly
            # enabled it via the Settings page (default OFF — auto-blocking
            # real traffic is destructive enough that it shouldn't be on by
            # default just because a container booted).
            auto_block_enabled = settings.get('autoBlock', False)
            if auto_block_enabled and severity == 'CRITICAL' and src_ip not in whitelist:
                try:
                    block_ip(src_ip)
                except Exception as e:
                    logger.error(f"Failed to block IP: {e}")

    def _classify_threat(self, threat_probs: np.ndarray) -> str:
        threat_classes = ['Benign', 'DoS', 'Port Scan', 'Brute Force', 'Web Attack']
        if len(threat_probs) == 0:
            return 'Unknown'
        return threat_classes[np.argmax(threat_probs)]
    
    def _compute_severity(self, anomaly_score: float, settings: dict = None) -> str:
        """
        Severity bands are driven by the Critical/High thresholds saved on
        the Settings page (defaults: 0.95 / 0.85) instead of fixed constants,
        so the sliders shown in the UI actually change detection behavior.
        """
        settings = settings or {}
        critical_threshold = settings.get('criticalThreshold', 0.95)
        high_threshold = settings.get('highThreshold', 0.85)
        if anomaly_score > critical_threshold:
            return 'CRITICAL'
        elif anomaly_score > high_threshold:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def start_capture(self, interface: str = 'eth0', packet_count: int = 0):
        logger.info(f"Starting packet capture on {interface}")
        try:
            sniff(
                iface=interface if interface and interface != 'auto' else None,
                prn=self.packet_callback,
                store=False,
                count=packet_count
            )
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            raise