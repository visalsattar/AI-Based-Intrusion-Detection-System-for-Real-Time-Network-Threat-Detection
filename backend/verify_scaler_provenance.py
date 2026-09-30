import pandas as pd
import numpy as np
import joblib
from sklearn.impute import SimpleImputer

p = "data/CICIDS2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(p)
df.columns = df.columns.str.strip()

X = df.drop(columns=["Label"]).select_dtypes(exclude=["object"]).copy()

# Match the documented preprocessing:
# inf/-inf -> maximum finite value in that column
for c in X.select_dtypes(include=[np.number]).columns:
    mask = np.isinf(X[c])
    if mask.any():
        finite = X.loc[~mask, c]
        X.loc[mask, c] = finite.max() if len(finite) else 0

# Match data_preprocessing.py:
# remaining NaN -> column mean
X = pd.DataFrame(
    SimpleImputer(strategy="mean").fit_transform(X),
    columns=X.columns,
)

s = joblib.load("models/feature_scaler.pkl")

computed_min = X.min().to_numpy()
computed_max = X.max().to_numpy()

print("columns_match =", list(X.columns) == list(s.feature_names_in_))
print("min_match     =", np.allclose(computed_min, s.data_min_))
print("max_match     =", np.allclose(computed_max, s.data_max_))

print()
print("MAX ABS MIN DIFFERENCE =", np.max(np.abs(computed_min - s.data_min_)))
print("MAX ABS MAX DIFFERENCE =", np.max(np.abs(computed_max - s.data_max_)))

print()
print("Columns with min mismatch:")
for i, (name, a, b) in enumerate(zip(X.columns, computed_min, s.data_min_)):
    if not np.isclose(a, b):
        print(i, name, "computed=", a, "scaler=", b)

print()
print("Columns with max mismatch:")
for i, (name, a, b) in enumerate(zip(X.columns, computed_max, s.data_max_)):
    if not np.isclose(a, b):
        print(i, name, "computed=", a, "scaler=", b)
