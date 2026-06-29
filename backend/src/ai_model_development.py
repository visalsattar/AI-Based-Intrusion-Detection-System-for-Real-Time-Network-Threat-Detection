# backend/src/ai_model_development.py
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model, Sequential
from tensorflow.keras.regularizers import l2
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
import numpy as np
import logging
from typing import Tuple, Dict
import joblib

logger = logging.getLogger(__name__)

class HybridIDSModel:
    """
    Hybrid ensemble: Autoencoder + Random Forest + CNN
    """
    
    def __init__(self, input_dim: int = 78, num_classes: int = 8):
        self.input_dim = input_dim
        self.num_classes = num_classes
        self.autoencoder = None
        self.encoder = None
        self.random_forest = None
        self.cnn_classifier = None
        self.history = {}
    
    def build_autoencoder(self, encoding_dim: int = 32) -> Tuple[Model, Model]:
        logger.info("Building Autoencoder...")
        
        inputs = keras.Input(shape=(self.input_dim,))
        encoded = layers.Dense(64, activation='relu', kernel_regularizer=l2(1e-5))(inputs)
        encoded = layers.Dropout(0.2)(encoded)
        encoded = layers.Dense(32, activation='relu', kernel_regularizer=l2(1e-5))(encoded)
        encoded = layers.Dropout(0.2)(encoded)
        encoded = layers.Dense(encoding_dim, activation='relu', name='encoding')(encoded)
        
        decoded = layers.Dense(32, activation='relu', kernel_regularizer=l2(1e-5))(encoded)
        decoded = layers.Dropout(0.2)(decoded)
        decoded = layers.Dense(64, activation='relu', kernel_regularizer=l2(1e-5))(decoded)
        decoded = layers.Dropout(0.2)(decoded)
        # NOTE: sigmoid was tested as an alternative (reasoning: inputs
        # are MinMax-scaled to [0,1], so a bounded output seemed like it
        # should help). It was tried and measured: linear gave ROC-AUC
        # 0.772, sigmoid gave 0.688 on the real held-out test set. Linear
        # is kept because it measurably performed better, not by default.
        decoded = layers.Dense(self.input_dim, activation='linear')(decoded)
        
        autoencoder = Model(inputs, decoded)
        autoencoder.compile(
            optimizer=keras.optimizers.Adam(learning_rate=1e-3),
            loss='mse'
        )
        
        encoder = Model(inputs, encoded)
        logger.info(f"Autoencoder built successfully")
        
        return autoencoder, encoder
    
    def build_random_forest(self, n_estimators: int = 200) -> RandomForestClassifier:
        logger.info("Building Random Forest...")
        
        rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=20,
            min_samples_split=10,
            min_samples_leaf=5,
            n_jobs=-1,
            random_state=42,
            class_weight='balanced',
            max_features='sqrt'
        )
        
        logger.info("Random Forest built successfully")
        return rf
    
    def build_cnn_classifier(self) -> Sequential:
        logger.info("Building CNN...")
        
        model = Sequential([
            layers.Input(shape=(100, self.input_dim)),
            
            layers.Conv1D(64, kernel_size=3, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.MaxPooling1D(pool_size=2),
            
            layers.Conv1D(128, kernel_size=3, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.MaxPooling1D(pool_size=2),
            
            layers.Conv1D(256, kernel_size=3, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            
            layers.GlobalAveragePooling1D(),
            
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.4),
            
            layers.Dense(self.num_classes, activation='softmax')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=1e-3),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        logger.info(f"CNN built with {model.count_params():,} parameters")
        return model
    
    def train_autoencoder(self, X_train: np.ndarray, 
                         validation_split: float = 0.2,
                         epochs: int = 50,
                         batch_size: int = 32) -> Dict:
        logger.info("Training Autoencoder on benign traffic only...")
        
        history = self.autoencoder.fit(
            X_train, X_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            verbose=1,
            callbacks=[
                keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=10,
                    restore_best_weights=True
                ),
                keras.callbacks.ReduceLROnPlateau(
                    monitor='val_loss',
                    factor=0.5,
                    patience=5,
                    min_lr=1e-6
                )
            ]
        )
        
        self.history['autoencoder'] = history.history
        logger.info(f"Autoencoder trained. Final val_loss: {history.history['val_loss'][-1]:.6f}")
        
        return history.history
    
    def train_random_forest(self, X_train: np.ndarray, y_train: np.ndarray) -> Dict:
        logger.info("Training Random Forest...")
        
        self.random_forest.fit(X_train, y_train)
        
        cv_scores = cross_val_score(
            self.random_forest, X_train, y_train,
            cv=5, scoring='f1_weighted', n_jobs=-1
        )
        
        logger.info(f"RF CV F1 Scores: mean={cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        
        feature_importance = self.random_forest.feature_importances_
        logger.info(f"Top 10 important features:")
        for idx in np.argsort(feature_importance)[-10:][::-1]:
            logger.info(f"  Feature {idx}: {feature_importance[idx]:.4f}")
        
        return {
            'cv_f1_mean': cv_scores.mean(),
            'cv_f1_std': cv_scores.std(),
            'feature_importance': feature_importance
        }
    
    def train_cnn(self, X_train_seq: np.ndarray, y_train: np.ndarray,
                 X_val_seq: np.ndarray, y_val: np.ndarray,
                 epochs: int = 100, batch_size: int = 64) -> Dict:
        logger.info("Training CNN...")
        
        history = self.cnn_classifier.fit(
            X_train_seq, y_train,
            validation_data=(X_val_seq, y_val),
            epochs=epochs,
            batch_size=batch_size,
            verbose=1,
            callbacks=[
                keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=15,
                    restore_best_weights=True
                ),
                keras.callbacks.ReduceLROnPlateau(
                    monitor='val_loss',
                    factor=0.5,
                    patience=5,
                    min_lr=1e-6
                )
            ]
        )
        
        self.history['cnn'] = history.history
        logger.info(f"CNN trained. Final val_accuracy: {history.history['val_accuracy'][-1]:.4f}")
        
        return history.history
    
    def ensemble_predict(self, X: np.ndarray, X_seq: np.ndarray = None) -> Tuple[np.ndarray, np.ndarray]:
        batch_size = X.shape[0]
        
        X_reconstructed = self.autoencoder.predict(X, batch_size=batch_size, verbose=0)
        reconstruction_error = np.mean(np.square(X - X_reconstructed), axis=1)
        anomaly_scores = 1 / (1 + np.exp(-reconstruction_error))
        
        rf_probs = self.random_forest.predict_proba(X)
        
        if X_seq is not None:
            cnn_probs = self.cnn_classifier.predict(X_seq, batch_size=batch_size, verbose=0)
        else:
            cnn_probs = rf_probs
        
        ensemble_probs = 0.6 * rf_probs + 0.4 * cnn_probs
        
        threat_probs = np.column_stack([anomaly_scores, ensemble_probs])
        
        return anomaly_scores, threat_probs
    
    def save_models(self, dir_path: str = 'models/'):
        import os
        os.makedirs(dir_path, exist_ok=True)
        
        self.autoencoder.save(f'{dir_path}/autoencoder.h5')
        self.cnn_classifier.save(f'{dir_path}/cnn_classifier.h5')
        joblib.dump(self.random_forest, f'{dir_path}/random_forest.pkl')
        
        logger.info(f"Models saved to {dir_path}")
    
    def load_models(self, dir_path: str = 'models/'):
        self.autoencoder = keras.models.load_model(f'{dir_path}/autoencoder.h5')
        self.cnn_classifier = keras.models.load_model(f'{dir_path}/cnn_classifier.h5')
        self.random_forest = joblib.load(f'{dir_path}/random_forest.pkl')
        
        logger.info(f"Models loaded from {dir_path}")
        
    # ==============================================================================
# PASTE EVERYTHING BELOW THIS LINE AT THE ABSOLUTE BOTTOM OF YOUR FILE
# Ensure there is NO indentation before the word 'def'
# ==============================================================================

def train_hybrid_ids_model(X_train: np.ndarray, y_train: np.ndarray,
                          X_val: np.ndarray, y_val: np.ndarray,
                          X_seq_train: np.ndarray, X_seq_val: np.ndarray,
                          y_seq_train: np.ndarray = None, y_seq_val: np.ndarray = None):
    """
    Complete training pipeline.

    NOTE: y_seq_train/y_seq_val are the labels ALIGNED to the sequence
    arrays (one label per window, not per original row). These must be
    passed separately from y_train/y_val because sequence construction
    (see sequence_builder.py) changes the number of samples -- a window
    of 100 rows with stride 10 produces fewer sequences than there were
    original rows, so y_train/y_val (one label per row) cannot be reused
    directly for the CNN, which trains one label per WINDOW.
    """
    logger.info("="*70)
    logger.info("HYBRID IDS MODEL TRAINING PIPELINE")
    logger.info("="*70)
    
    # Initialize model
    hybrid_model = HybridIDSModel(input_dim=X_train.shape[1], num_classes=len(np.unique(y_train)))
    
    # Build models
    hybrid_model.autoencoder, hybrid_model.encoder = hybrid_model.build_autoencoder(encoding_dim=32)
    hybrid_model.random_forest = hybrid_model.build_random_forest(n_estimators=200)
    hybrid_model.cnn_classifier = hybrid_model.build_cnn_classifier()
    
    # Train on benign only (separate from malicious)
    benign_mask = (y_train == 0)  # Assuming 0 = Benign
    X_benign = X_train[benign_mask]
    
    logger.info(f"\nTraining autoencoder on {len(X_benign)} benign samples...")
    hybrid_model.train_autoencoder(X_benign, epochs=50)
    
    logger.info(f"\nTraining Random Forest on full training set ({len(X_train)} samples)...")
    hybrid_model.train_random_forest(X_train, y_train)
    
    if y_seq_train is None or y_seq_val is None:
        raise ValueError(
            "y_seq_train and y_seq_val are required -- the CNN trains on "
            "one label per WINDOW, which is a different length than the "
            "original per-row y_train/y_val. Pass the labels returned by "
            "sequence_builder.build_sequences(), not the flat row labels."
        )
    if len(X_seq_train) != len(y_seq_train):
        raise ValueError(
            f"X_seq_train has {len(X_seq_train)} sequences but y_seq_train "
            f"has {len(y_seq_train)} labels -- these must match exactly."
        )

    logger.info(f"\nTraining CNN on sequence data ({len(X_seq_train)} sequences)...")
    hybrid_model.train_cnn(X_seq_train, y_seq_train, X_seq_val, y_seq_val, epochs=100)
    
    # Save models
    hybrid_model.save_models('models/')
    
    logger.info("\n" + "="*70)
    logger.info("TRAINING COMPLETE")
    logger.info("="*70)
    
    return hybrid_model