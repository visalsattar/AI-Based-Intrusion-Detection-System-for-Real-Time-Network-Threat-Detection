import glob, sys
import pandas as pd

pattern = sys.argv[1] if len(sys.argv) > 1 else "data/CICIDS2017/*.csv"
files = glob.glob(pattern)
if not files:
    sys.exit(f"No CSVs matched: {pattern}")

cols = ["Subflow Fwd Packets", "Total Fwd Packets", "Init_Win_bytes_forward",
        "Down/Up Ratio", "Active Mean"]
frames = []
for f in files:
    d = pd.read_csv(f, skipinitialspace=True, encoding="latin-1", low_memory=False)
    d.columns = d.columns.str.strip()
    frames.append(d[cols])
df = pd.concat(frames, ignore_index=True)

print("rows:", len(df), "files:", len(files))
print("subflow==total fwd:", (df["Subflow Fwd Packets"] == df["Total Fwd Packets"]).mean())
print("init_win -1 share:", (df["Init_Win_bytes_forward"] == -1).mean())
print("down/up non-integer share:", (df["Down/Up Ratio"] % 1 != 0).mean())
print("active mean nonzero share:", (df["Active Mean"] != 0).mean())