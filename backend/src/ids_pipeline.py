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
                'packet_list': []
            }
        
        flow = self.flow_tracker[flow_key]
        flow['packets'] += 1
        flow['bytes'] += len(packet)
        flow['last_seen'] = datetime.now()
        flow['packet_list'].append(packet)
        
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
        """Extract CICIDS2017-compatible features from a live flow[cite: 4]."""
        if flow_key not in self.flow_tracker:
            return None

        flow = self.flow_tracker[flow_key]
        packets = flow['packet_list']

        flow_duration_s = (flow['last_seen'] - flow['first_seen']).total_seconds()
        flow_duration = flow_duration_s if flow_duration_s > 0 else 0.001
        flow_duration_us = flow_duration * 1_000_000 

        num_packets = flow['packets']
        total_bytes = flow['bytes']

        pkt_sizes = np.array([len(p) for p in packets], dtype=np.float64)
        pkt_size_mean = float(pkt_sizes.mean()) if len(pkt_sizes) else 0.0
        pkt_size_std = float(pkt_sizes.std()) if len(pkt_sizes) > 1 else 0.0
        pkt_size_max = float(pkt_sizes.max()) if len(pkt_sizes) else 0.0
        pkt_size_min = float(pkt_sizes.min()) if len(pkt_sizes) else 0.0

        if len(packets) > 1:
            pkt_times = np.array(
                [float(p.time) for p in packets], dtype=np.float64
            )
            iat = np.diff(pkt_times) * 1_000_000 
            iat_mean = float(iat.mean())
            iat_std = float(iat.std()) if len(iat) > 1 else 0.0
            iat_max = float(iat.max())
            iat_min = float(iat.min())
        else:
            iat_mean = iat_std = iat_max = iat_min = 0.0

        syn_count = fin_count = rst_count = psh_count = ack_count = urg_count = 0
        for p in packets:
            if TCP in p:
                f = p[TCP].flags
                syn_count += int(f.S)
                fin_count += int(f.F)
                rst_count += int(f.R)
                psh_count += int(f.P)
                ack_count += int(f.A)
                urg_count += int(f.U)

        flow_bytes_per_s = total_bytes / flow_duration if flow_duration > 0 else 0.0
        flow_packets_per_s = num_packets / flow_duration if flow_duration > 0 else 0.0

        base_features = np.array([
            flow_duration_us,
            num_packets,
            num_packets,            
            0,                       
            total_bytes,
            total_bytes,             
            0,                       
            pkt_size_max,
            pkt_size_min,
            pkt_size_mean,
            pkt_size_std,
            flow_bytes_per_s,
            flow_packets_per_s,
            iat_mean,
            iat_std,
            iat_max,
            iat_min,
            syn_count,
            fin_count,
            rst_count,
            psh_count,
            ack_count,
            urg_count,
            1 if flow['protocol'] == 6 else 0,
        ], dtype=np.float32)

        features = np.zeros(78, dtype=np.float32)
        features[:len(base_features)] = base_features

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
                'dst_ip': flow_key[1][0],
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