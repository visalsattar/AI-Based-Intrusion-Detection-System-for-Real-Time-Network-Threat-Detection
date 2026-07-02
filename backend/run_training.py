"""
Standalone training script — use this instead of `python main.py --mode train`.

main.py imports Flask, SocketIO, Scapy, and Redis at module level. On Windows,
sklearn's joblib backend spawns child processes for n_jobs=-1, and those child
processes re-import the module. The Flask/Socket.IO globals interfere with the
child process initialisation, causing cross_val_score to deadlock silently.

This script imports ONLY what training needs: no Flask, no SocketIO, no Scapy.
"""
import os
import sys
import logging

# Must be set before any other imports so child processes (joblib workers)
# inherit it and don't try to re-run __main__ code.
if __name__ != '__main__':
    sys.exit(0)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(name)s] [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler('logs/training.log', mode='w'),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("IDS-Training")

# All training imports here — clean slate, no web framework
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from sequence_builder import build_cnn_sequences  # noqa: E402
from ai_model_development import train_hybrid_ids_model  # noqa: E402

os.makedirs('models',               exist_ok=True)
os.makedirs('data/preprocessed',   exist_ok=True)
os.makedirs('logs',                 exist_ok=True)

CSV = 'data/preprocessed/CICIDS2017_cleaned.csv'
if not os.path.exists(CSV):
    logger.error(f"Preprocessed CSV not found: {CSV}")
    logger.error("Run preprocessing first: python main.py --mode preprocess --dataset <csv>")
    sys.exit(1)

logger.info("="*70)
logger.info("HYBRID IDS TRAINING (standalone — no Flask/SocketIO loaded)")
logger.info("="*70)

logger.info("Building sequence windows from preprocessed CSV ...")
data = build_cnn_sequences(CSV, window_size=100, stride=10)
logger.info(f"Sequences built: {len(data['X_seq_train'])} train, "
            f"{len(data['X_seq_val'])} val, {len(data['X_seq_test'])} test")

train_hybrid_ids_model(
    data['X_train_flat'], data['y_train_flat'],
    data['X_val_flat'],   data['y_val_flat'],
    data['X_seq_train'],  data['X_seq_val'],
    data['y_seq_train'],  data['y_seq_val'],
)

# Persist test set for model_evaluation.py
np.save('data/preprocessed/X_test_flat.npy', data['X_test_flat'])
np.save('data/preprocessed/y_test_flat.npy', data['y_test_flat'])
logger.info("Test set saved to data/preprocessed/ for future evaluation.")

logger.info("="*70)
logger.info("TRAINING COMPLETE — models saved to models/")
logger.info("="*70)
