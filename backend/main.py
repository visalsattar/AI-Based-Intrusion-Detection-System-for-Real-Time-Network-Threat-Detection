# backend/main.py
"""
AI-Based Intrusion Detection System (IDS) - Production Orchestrator.

This module acts as the central control plane for the IDS. It handles:
1. Data Preprocessing (CICIDS2017 pipeline)
2. Hybrid AI Model Training (CNN-Autoencoder)
3. Real-time Packet Capture Pipeline (Scapy/IDS)
4. Flask/Socket.IO Dashboard API & React Static File Hosting
"""

# 1. Critical Async Patching (MUST be the very first thing executed)
#
# EVENTLET_NO_GREENDNS must be set BEFORE eventlet is imported. Eventlet
# normally monkey-patches socket.getaddrinfo with its own DNS resolver
# ("greendns"), which routes hostname lookups through its own resolver
# logic instead of the OS's. That resolver does not reliably handle
# Docker's internal DNS server for service-name lookups (e.g. resolving
# 'redis' to the redis container's IP) -- it fails with a timeout every
# time, regardless of retries or how long Redis has already been up.
# This is NOT the same as the earlier startup-ordering race (which the
# docker-compose healthcheck already fixed); it's eventlet's resolver
# itself misbehaving inside Docker, so retries alone can never fix it.
# Disabling greendns falls back to the normal OS resolver, which talks
# to Docker's embedded DNS correctly.
import os
os.environ['EVENTLET_NO_GREENDNS'] = 'yes'

import eventlet
eventlet.monkey_patch()

# 2. Standard Library Imports
import os
import sys
import time
import argparse
import logging
import threading
from pathlib import Path

# 3. Third-Party Imports
import numpy as np
from flask import Flask, send_from_directory
from flask_socketio import SocketIO
from redis import Redis
from dotenv import load_dotenv

# Load backend/.env (if present) BEFORE anything reads os.environ, so
# ABUSEIPDB_API_KEY and friends are available to threat_intel_service.py
# without ever touching plaintext Redis storage. Safe to skip silently
# if no .env file exists (e.g. in CI or when using real env vars directly).
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

# 4. Environment & Path Setup
# Dynamically find the React build folder and set up system paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, 'src'))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'frontend', 'build'))

# 5. Local Application Imports
from data_preprocessing import CICIDSPreprocessor
from ai_model_development import HybridIDSModel, train_hybrid_ids_model
from ids_pipeline import RealTimeIDSPipeline
from redis_alert_bridge import start_redis_alert_bridge
from network_utils import list_interfaces
from routes import register_routes

# 6. Global Application Initialization
# Initialize Flask using the absolute path to the React frontend
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='/')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Optional Redis connection. All alert data — real or none — flows through
# the 'ids:alerts' stream, written by RealTimeIDSPipeline once packet
# capture is running, and read here by both the REST API and the live
# Socket.IO bridge below. There is no synthetic data path.
def _connect_redis(max_attempts=5, base_delay=1.5):
    """Connect to Redis with retry+backoff.

    A single failed attempt previously disabled Redis for the entire
    container lifetime -- but Docker's internal DNS for service names
    (e.g. 'redis') can transiently fail to resolve right at container
    startup, especially right after a restart, before fully settling.
    That's a timing race, not a real outage, so it's worth a few
    short retries before giving up.
    """
    host = os.environ.get('REDIS_HOST', 'redis')
    log = logging.getLogger("IDS-Orchestrator")
    for attempt in range(1, max_attempts + 1):
        try:
            client = Redis(host=host, port=6379, decode_responses=True, socket_connect_timeout=2)
            client.ping()
            if attempt > 1:
                log.info(f"Redis connected on attempt {attempt}/{max_attempts}.")
            return client
        except Exception as e:
            if attempt < max_attempts:
                delay = base_delay * attempt
                log.warning(f"Redis connection attempt {attempt}/{max_attempts} failed "
                            f"({host}): {e} -- retrying in {delay:.1f}s.")
                time.sleep(delay)
            else:
                log.warning(f"Redis connection failed after {max_attempts} attempts "
                            f"({host}): {e}. Continuing without Redis -- "
                            f"history/settings/live-alerts will be unavailable "
                            f"until the process is restarted.")
                return None

redis_client = _connect_redis()

# Activate API routes (Redis-aware so History/Threat-Intel read real data)
register_routes(app, redis_client)

_bridge_lock = threading.Lock()
_bridge_started = False

@socketio.on('connect')
def _handle_socket_connect():
    """
    Starts the Redis -> Socket.IO alert bridge once, on first client
    connection. This tails the real 'ids:alerts' stream that
    RealTimeIDSPipeline writes to during packet capture (see
    run_ids_capture / AUTO_CAPTURE below) and pushes each new alert to
    every connected dashboard client live.
    """
    global _bridge_started
    with _bridge_lock:
        if _bridge_started:
            return
        socketio.start_background_task(start_redis_alert_bridge, socketio, redis_client)
        _bridge_started = True


def resolve_interface(requested: str) -> str:
    """
    Turns 'auto' (or a bad/missing interface name) into a real interface
    that actually exists on this host, instead of hardcoding 'eth0' — which
    doesn't exist on most Docker Desktop / Windows / Wi-Fi setups.
    """
    interfaces = list_interfaces()
    names = {i['name'] for i in interfaces}

    if requested and requested != 'auto' and requested in names:
        return requested

    # Prefer the first interface that's up, has an IPv4 address, and isn't loopback
    for i in interfaces:
        if i['is_up'] and i['ipv4'] and not i['name'].lower().startswith(('lo', 'loopback')):
            return i['name']

    # Last resort: whatever is up, even without a detected IPv4
    for i in interfaces:
        if i['is_up']:
            return i['name']

    return requested or 'eth0'

# 7. Enterprise-Grade Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(name)s] [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler('logs/ids.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("IDS-Orchestrator")


def setup_environment():
    """Ensures required directory tree exists to prevent FileNotFoundError."""
    required_dirs = ['models', 'data', 'data/preprocessed', 'logs']
    for directory in required_dirs:
        Path(directory).mkdir(parents=True, exist_ok=True)
    logger.info("Environment directories verified and ready.")


def execute_preprocessing(dataset_path: str):
    """Transforms raw CSV data into normalized features for model ingestion."""
    logger.info(f"Initiating preprocessing pipeline for: {dataset_path}")
    try:
        preprocessor = CICIDSPreprocessor(dataset_name='CICIDS2017')
        df_clean = preprocessor.preprocess_pipeline(
            file_path=dataset_path,
            output_path='data/preprocessed/CICIDS2017_cleaned.csv'
        )
        logger.info(f"Data cleaned. Final feature set shape: {df_clean.shape}")
    except Exception as e:
        # Added exc_info=True so the logs show exactly which line broke
        logger.error(f"Preprocessing pipeline failed: {e}", exc_info=True)
        sys.exit(1)


def execute_model_training():
    """Trains the Hybrid CNN-Autoencoder model using temporal sequences."""
    logger.info("Initiating hybrid model training...")
    from sequence_builder import build_cnn_sequences
    
    try:
        data = build_cnn_sequences('data/preprocessed/CICIDS2017_cleaned.csv', window_size=100, stride=10)
        
        train_hybrid_ids_model(
            data['X_train_flat'], data['y_train_flat'],
            data['X_val_flat'], data['y_val_flat'],
            data['X_seq_train'], data['X_seq_val'],
            data['y_seq_train'], data['y_seq_val']
        )
        
        np.save('data/preprocessed/X_test_flat.npy', data['X_test_flat'])
        np.save('data/preprocessed/y_test_flat.npy', data['y_test_flat'])
        
        logger.info("Training finished successfully. Model and test-sets persisted.")
    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        sys.exit(1)


def run_ids_capture(interface: str):
    """Initializes the real-time packet processing pipeline against a real NIC."""
    resolved = resolve_interface(interface)
    if resolved != interface:
        logger.info(f"Interface '{interface}' resolved to real interface '{resolved}'")
    logger.info(f"System entering IDS mode on interface: {resolved}")

    model_path = os.path.join(BASE_DIR, "models", "autoencoder.h5")
    scaler_path = os.path.join(BASE_DIR, "models", "feature_scaler.pkl")
    if not (os.path.exists(model_path) and os.path.exists(scaler_path)):
        logger.error(
            "Cannot start packet capture — trained model artifacts are missing "
            f"({model_path}, {scaler_path}). Run `python main.py --mode preprocess --dataset <csv>` "
            "then `python main.py --mode train` first."
        )
        return

    try:
        ids = RealTimeIDSPipeline(
            model_path=model_path,
            feature_extractor_path=scaler_path,
            alert_threshold=0.85,
            packet_batch_size=50
        )
        ids.start_capture(interface=resolved)
    except PermissionError as e:
        logger.error(
            f"IDS Capture failed — insufficient privileges to open a raw socket on '{resolved}': {e}. "
            "In Docker, run the container with --cap-add=NET_RAW --cap-add=NET_ADMIN "
            "(or `network_mode: host` in docker-compose), or run main.py as root/Administrator."
        )
    except Exception as e:
        logger.error(f"IDS Capture failure: {e}", exc_info=True)


def run_production_dashboard():
    """Serves the React frontend, bridges the WebSocket API, and — if
    AUTO_CAPTURE=true — runs real packet capture in-process so a single
    container can both detect and display intrusions without a second
    process. Off by default since it needs raw-socket privileges
    (NET_RAW/NET_ADMIN) that most container hosts don't grant unless asked."""
    logger.info("Loading Dashboard API and React Frontend...")

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve_frontend(path):
        if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        return send_from_directory(app.static_folder, 'index.html')

    if os.environ.get('AUTO_CAPTURE', 'false').lower() == 'true':
        capture_interface = os.environ.get('CAPTURE_INTERFACE', 'auto')
        logger.info(f"AUTO_CAPTURE enabled — starting packet capture thread (interface={capture_interface})")
        capture_thread = threading.Thread(
            target=run_ids_capture, args=(capture_interface,), daemon=True
        )
        capture_thread.start()
    else:
        logger.info(
            "AUTO_CAPTURE not enabled — dashboard will show real historical/Threat-Intel "
            "data but no new alerts until you either set AUTO_CAPTURE=true (in-process) "
            "or run `python main.py --mode ids --interface <name>` as a separate process."
        )

    socketio.run(
        app, 
        host='0.0.0.0', 
        port=5000, 
        debug=False, 
        allow_unsafe_werkzeug=True
    )


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description='AI-Based Intrusion Detection System')
    parser.add_argument('--mode', choices=['preprocess', 'train', 'ids', 'dashboard'], 
                        default='dashboard', help='Run mode selection')
    parser.add_argument('--dataset', help='Required for preprocess mode')
    parser.add_argument('--interface', default='eth0', help='Network interface for capture')
    
    args = parser.parse_args()
    setup_environment()
    
    if args.mode == 'preprocess':
        if not args.dataset:
            logger.error("Usage: --mode preprocess --dataset <path_to_csv>")
            sys.exit(1)
        execute_preprocessing(args.dataset)
    elif args.mode == 'train':
        execute_model_training()
    elif args.mode == 'ids':
        run_ids_capture(args.interface)
    else:
        run_production_dashboard()

if __name__ == '__main__':
    main()