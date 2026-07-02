# backend/src/data_preprocessing.py
import pandas as pd
import numpy as np
import logging
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.impute import SimpleImputer
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CICIDSPreprocessor:
    """
    Handles CICIDS2017 & UNSW-NB15 dataset preprocessing.

    Binary mode (default, backward-compatible):
        BENIGN → 0, every attack type → 1.
        All existing trained models expect this encoding.

    Multi-class mode (--multiclass flag in main.py):
        BENIGN → 0, each distinct attack label → a unique integer in
        alphabetical order (e.g. Bot→1, DDoS→2, DoS Hulk→3 ...).
        A models/label_map.json is written alongside the preprocessed CSV
        so the live pipeline can translate integer predictions back to
        human-readable names ("DDoS", "Port Scan", etc.) in dashboard alerts.
        To activate, retrain with `python main.py --mode train --multiclass`.
    """

    CICIDS_FEATURE_COLS = [
        'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration',
        'Total Fwd Packets', 'Total Backward Packets', 
        # ... (full list from previous code)
    ]
    
    def __init__(self, dataset_name: str = 'CICIDS2017'):
        self.dataset_name = dataset_name
        self.scaler = MinMaxScaler()
        self.label_encoder = LabelEncoder()
        self.feature_cols = None
        self.stats = {
            'original_rows': 0,
            'missing_value_counts': {},
            'infinite_value_counts': {},
            'dropped_rows': 0,
            'normalization_params': {}
        }
    
    def load_dataset(self, file_path: str) -> pd.DataFrame:
        logger.info(f"Loading dataset from {file_path}")
        try:
            df = pd.read_csv(file_path)
            self.stats['original_rows'] = len(df)
            logger.info(f"Loaded {len(df)} rows, {len(df.columns)} columns")
            return df
        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            raise
    
    def handle_infinite_values(self, df: pd.DataFrame) -> pd.DataFrame:
        logger.info("Detecting and handling infinite values...")
        
        infinite_cols = {}
        for col in df.select_dtypes(include=[np.number]).columns:
            inf_mask = np.isinf(df[col])
            if inf_mask.any():
                infinite_cols[col] = inf_mask.sum()
                self.stats['infinite_value_counts'][col] = int(inf_mask.sum())
        
        if infinite_cols:
            logger.warning(f"Found infinite values in {len(infinite_cols)} columns")
            for col in infinite_cols.keys():
                finite_mask = np.isfinite(df[col])
                if finite_mask.any():
                    max_finite = df.loc[finite_mask, col].max()
                    df[col] = df[col].replace([np.inf, -np.inf], max_finite)
                    logger.info(f"  Replaced infinite in '{col}' with {max_finite:.6f}")
                else:
                    df[col] = 0
                    logger.warning(f"  All values in '{col}' infinite. Filled with 0")
        
        return df
    
    def handle_missing_values(self, df: pd.DataFrame, strategy: str = 'mean') -> pd.DataFrame:
        logger.info(f"Handling missing values with strategy: {strategy}")
        
        missing_before = df.isnull().sum()
        self.stats['missing_value_counts'] = missing_before[missing_before > 0].to_dict()
        
        if missing_before.sum() == 0:
            logger.info("No missing values detected")
            return df
        
        if strategy == 'drop':
            df = df.dropna()
            self.stats['dropped_rows'] = self.stats['original_rows'] - len(df)
            logger.info(f"Dropped {self.stats['dropped_rows']} rows")
        elif strategy in ['mean', 'median']:
            imputer = SimpleImputer(strategy=strategy)
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            df[numeric_cols] = imputer.fit_transform(df[numeric_cols])
            logger.info(f"Imputed using {strategy}")
        
        return df
    
    def normalize_features(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        logger.info("Normalizing features using MinMaxScaler...")
        
        label_col = 'Label' if 'Label' in df.columns else None
        
        if label_col:
            X = df.drop(columns=[label_col])
            y = df[label_col]
        else:
            X = df
            y = None
        
        if fit:
            X_scaled = self.scaler.fit_transform(X)
            self.stats['normalization_params'] = {
                'data_min': self.scaler.data_min_.tolist(),
                'data_max': self.scaler.data_max_.tolist()
            }
        else:
            X_scaled = self.scaler.transform(X)
        
        df_normalized = pd.DataFrame(X_scaled, columns=X.columns, index=df.index)
        
        if y is not None:
            df_normalized[label_col] = y.values
        
        return df_normalized
    
    def encode_labels(self, df: pd.DataFrame, label_col: str = 'Label', fit: bool = True) -> pd.DataFrame:
        if label_col not in df.columns:
            logger.warning(f"Label column '{label_col}' not found")
            return df
        
        logger.info(f"Encoding labels in column '{label_col}'")
        
        if fit:
            df[label_col] = self.label_encoder.fit_transform(df[label_col].astype(str))
            classes = self.label_encoder.classes_
            logger.info(f"Fitted encoder on {len(classes)} classes")
        else:
            df[label_col] = self.label_encoder.transform(df[label_col].astype(str))
        
        return df
    
    def preprocess_pipeline(self, file_path: str, output_path: str = None,
                             multiclass: bool = False,
                             label_map_path: str = None) -> pd.DataFrame:
        """
        Full preprocessing pipeline.

        multiclass: when False (default), BENIGN→0 and all attacks→1
                    (backward-compatible with existing trained models).
                    When True, each distinct attack label gets its own
                    integer (BENIGN always=0; others sorted alphabetically),
                    and a label_map.json is written so the live pipeline can
                    name attack types in dashboard alerts.
        label_map_path: where to write label_map.json in multiclass mode.
                    Defaults to models/label_map.json relative to the
                    preprocessed CSV, so main.py training flow auto-finds it.
        """
        logger.info("\n" + "="*70)
        logger.info(f"STARTING PREPROCESSING PIPELINE (multiclass={multiclass})")
        logger.info("="*70)

        df = self.load_dataset(file_path)
        df = self.handle_infinite_values(df)
        df = self.handle_missing_values(df, strategy='mean')

        # 1. Strip hidden spaces from column names (' Label' → 'Label')
        df.columns = df.columns.str.strip()

        # 2. Encode labels
        label_map = None
        if 'Label' in df.columns:
            if multiclass:
                # Map each unique attack type to its own integer.
                # BENIGN is always 0; all others are sorted alphabetically
                # so the mapping is deterministic across runs and machines.
                attack_labels = sorted(
                    lbl for lbl in df['Label'].unique() if lbl != 'BENIGN'
                )
                label_map = {0: 'Benign'}
                for i, lbl in enumerate(attack_labels, start=1):
                    label_map[i] = lbl
                reverse = {'BENIGN': 0}
                reverse.update({lbl: i for i, lbl in label_map.items() if i > 0})
                df['Label'] = df['Label'].map(reverse).fillna(0).astype(int)
                logger.info(
                    f"Multi-class label encoding: {len(label_map)} classes — "
                    + ", ".join(f"{k}={v}" for k, v in label_map.items())
                )
            else:
                # Binary (default): BENIGN=0, any attack=1
                df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
                logger.info("Binary label encoding: BENIGN=0, all attacks=1")

        # 3. Drop remaining text columns (IP addresses etc.) so math doesn't crash
        df = df.select_dtypes(exclude=['object'])

        df = self.normalize_features(df, fit=True)
        df = self.encode_labels(df, fit=True)

        if output_path:
            df.to_csv(output_path, index=False)
            logger.info(f"Saved preprocessed dataset to {output_path}")

        # Write label_map.json in multi-class mode so the pipeline can
        # translate RF integer predictions to named attack types at runtime.
        if multiclass and label_map is not None:
            import json, os
            if label_map_path is None:
                base = os.path.dirname(output_path) if output_path else '.'
                label_map_path = os.path.join(
                    os.path.dirname(base), 'models', 'label_map.json'
                )
            os.makedirs(os.path.dirname(label_map_path) or '.', exist_ok=True)
            # JSON keys must be strings; store as {"0":"Benign","1":"DDoS",...}
            with open(label_map_path, 'w') as f:
                json.dump({str(k): v for k, v in label_map.items()}, f, indent=2)
            logger.info(f"Saved multi-class label map to {label_map_path}")
            self.label_map = label_map  # expose for callers / tests

        logger.info("\n" + "="*70)
        logger.info("PREPROCESSING COMPLETE")
        logger.info("="*70 + "\n")

        return df