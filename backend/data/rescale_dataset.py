"""
Fixes the scaling bug found in data.zip's CICIDS2017_cleaned.csv.

PROBLEM FOUND:
data.zip's data/preprocessed/CICIDS2017_cleaned.csv is scaled with
StandardScaler (mean ~0, std ~1, includes negative values), NOT with
the MinMaxScaler ([0.0, 1.0] range) that models/feature_scaler.pkl
actually is and that the current autoencoder.h5 was trained against.
Evaluating against the StandardScaler version gave badly degraded,
misleading metrics for ALL THREE models (not just the autoencoder) --
the data was the problem, not the models.

FIX:
data.zip also contains the original RAW (unscaled) CICIDS2017 file:
data/CICIDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
This raw file has identical row count and identical label counts
(BENIGN=97718, DDoS=128027) to CICIDS2017_cleaned.csv -- confirming
it's the same underlying data, just scaled wrong in the zip.

This script re-scales the RAW file using the already-fitted
models/feature_scaler.pkl (transform only, never re-fit), producing a
correctly MinMax-scaled [0.0, 1.0] CSV consistent with how the current
autoencoder.h5 was trained.

Usage:
    python rescale_dataset.py <raw_csv_path> <scaler_path> <output_csv_path>
"""
import sys
import pandas as pd
import numpy as np
import joblib


def rescale(raw_csv_path: str, scaler_path: str, output_csv_path: str):
    print(f"Loading raw data from {raw_csv_path} ...")
    df = pd.read_csv(raw_csv_path)
    df.columns = [c.strip() for c in df.columns]

    scaler = joblib.load(scaler_path)
    feat_cols = list(scaler.feature_names_in_)

    X = df[feat_cols].copy()
    X = X.replace([np.inf, -np.inf], np.nan)
    n_missing = int(X.isna().sum().sum())
    if n_missing:
        print(f"Filling {n_missing} inf/NaN cells with column means "
              f"(same handling as data_preprocessing.py).")
        X = X.fillna(X.mean(numeric_only=True))

    X_scaled = scaler.transform(X)
    print(f"Scaled range: [{X_scaled.min():.6f}, {X_scaled.max():.6f}] "
          f"(should be [0.0, 1.0])")

    y = (df['Label'].str.strip() != 'BENIGN').astype(int)
    print(f"Label distribution after encoding:\n{y.value_counts()}")

    out = pd.DataFrame(X_scaled, columns=feat_cols)
    out['Label'] = y.values
    out.to_csv(output_csv_path, index=False)
    print(f"Saved correctly-scaled file to {output_csv_path}: {out.shape}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    rescale(sys.argv[1], sys.argv[2], sys.argv[3])
