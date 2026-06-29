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
    Handles CICIDS2017 & UNSW-NB15 dataset preprocessing
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
    
    def preprocess_pipeline(self, file_path: str, output_path: str = None) -> pd.DataFrame:
        logger.info("\n" + "="*70)
        logger.info("STARTING PREPROCESSING PIPELINE")
        logger.info("="*70)
        
        df = self.load_dataset(file_path)
        df = self.handle_infinite_values(df)
        df = self.handle_missing_values(df, strategy='mean')
        
        # Standardize column names and encode labels:
        # 1. Remove hidden spaces from column names (turns ' Label' into 'Label')
        df.columns = df.columns.str.strip()
        
        # 2. Convert strings to numbers (0=Safe, 1=Attack)
        if 'Label' in df.columns:
            df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
            
        # 3. Drop any remaining text columns (like IP addresses) so math doesn't crash
        df = df.select_dtypes(exclude=['object'])

        df = self.normalize_features(df, fit=True)
        df = self.encode_labels(df, fit=True)
        
        if output_path:
            df.to_csv(output_path, index=False)
            logger.info(f"Saved preprocessed dataset to {output_path}")
        
        logger.info("\n" + "="*70)
        logger.info("PREPROCESSING COMPLETE")
        logger.info("="*70 + "\n")
        
        return df