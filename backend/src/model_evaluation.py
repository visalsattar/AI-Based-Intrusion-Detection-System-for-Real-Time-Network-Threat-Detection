"""
Model evaluation script: computes real, verified metrics for all three
models (Autoencoder, Random Forest, CNN) against a held-out test set
that none of them saw during training.

This consolidates the evaluation logic verified during the bug-fixing
session that produced the numbers reported in Thesis Chapter 7. Run
this any time after main.py --mode train to regenerate real_metrics.json.

Usage:
    python src/model_evaluation.py [path_to_preprocessed_csv]
"""
import sys
import os
import json
import numpy as np
import joblib
import tensorflow as tf
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score
)

sys.path.insert(0, os.path.dirname(__file__))
from sequence_builder import build_cnn_sequences


def evaluate_autoencoder(ae, X_train, y_train, X_test, y_test, percentile=90):
    """
    Threshold derived from benign TRAINING data only (never from test
    labels, to avoid biasing the reported metrics). Default percentile
    is 90, which was found during development to give the best F1
    trade-off for this dataset (see Table 7.1a in the thesis) -- this
    is not a guaranteed-best value for other datasets, and re-running
    the percentile sweep is recommended if the underlying data changes
    substantially.
    """
    X_train_benign = X_train[y_train == 0]
    train_mse = np.mean(
        np.square(X_train_benign - ae.predict(X_train_benign, verbose=0)), axis=1
    )
    threshold = np.percentile(train_mse, percentile)

    test_mse = np.mean(np.square(X_test - ae.predict(X_test, verbose=0)), axis=1)
    y_pred = (test_mse > threshold).astype(int)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (None, None, None, None)

    return {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred, zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, zero_division=0)),
        'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
        'roc_auc': float(roc_auc_score(y_test, test_mse)),
        'threshold': float(threshold),
        'threshold_percentile': percentile,
        'confusion_matrix': {
            'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)
        } if tn is not None else None
    }


def evaluate_classifier(model, X_test, y_test, is_keras=False):
    """Shared evaluation for Random Forest and CNN (both supervised)."""
    if is_keras:
        y_pred = np.argmax(model.predict(X_test, verbose=0), axis=1)
    else:
        y_pred = model.predict(X_test)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (None, None, None, None)

    return {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred, zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, zero_division=0)),
        'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
        'confusion_matrix': {
            'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)
        } if tn is not None else None
    }


def run_full_evaluation(preprocessed_csv_path: str,
                         models_dir: str = 'models',
                         output_path: str = 'models/real_metrics.json'):
    print(f"Loading and re-splitting data from {preprocessed_csv_path} ...")
    print("(Uses the same window_size/stride as training -- changing these "
          "without retraining will produce a shape mismatch error, which "
          "is intentional: it signals the saved model and this evaluation "
          "are no longer using consistent data.)")
    data = build_cnn_sequences(preprocessed_csv_path, window_size=100, stride=10)

    X_train, y_train = data['X_train_flat'], data['y_train_flat']
    X_test, y_test = data['X_test_flat'], data['y_test_flat']
    X_seq_test, y_seq_test = data['X_seq_test'], data['y_seq_test']

    results = {
        'methodology': (
            'All metrics computed on a held-out test set none of the '
            'models saw during training or threshold selection. '
            'Autoencoder threshold derived from benign training '
            'reconstruction error only.'
        ),
        'test_set_size': int(len(y_test)),
    }

    ae_path = os.path.join(models_dir, 'autoencoder.h5')
    if os.path.exists(ae_path):
        print("\nEvaluating Autoencoder...")
        ae = tf.keras.models.load_model(ae_path, compile=False)
        results['autoencoder'] = evaluate_autoencoder(ae, X_train, y_train, X_test, y_test)
        print(json.dumps(results['autoencoder'], indent=2))
    else:
        print(f"\nSkipping Autoencoder: {ae_path} not found.")

    rf_path = os.path.join(models_dir, 'random_forest.pkl')
    if os.path.exists(rf_path):
        print("\nEvaluating Random Forest...")
        rf = joblib.load(rf_path)
        results['random_forest'] = evaluate_classifier(rf, X_test, y_test, is_keras=False)
        print(json.dumps(results['random_forest'], indent=2))
    else:
        print(f"\nSkipping Random Forest: {rf_path} not found.")

    cnn_path = os.path.join(models_dir, 'cnn_classifier.h5')
    if os.path.exists(cnn_path):
        print("\nEvaluating CNN...")
        cnn = tf.keras.models.load_model(cnn_path, compile=False)
        results['cnn'] = evaluate_classifier(cnn, X_seq_test, y_seq_test, is_keras=True)
        print(json.dumps(results['cnn'], indent=2))
    else:
        print(f"\nSkipping CNN: {cnn_path} not found.")

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved consolidated results to {output_path}")
    return results


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else \
        "data/preprocessed/CICIDS2017_cleaned_FIXED.csv"
    run_full_evaluation(path)
