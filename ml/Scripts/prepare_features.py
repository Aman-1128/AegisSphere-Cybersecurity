import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_FILE = PROJECT_ROOT / "datasets" / "ml_dataset_clean.csv"
OUTPUT_FILE = PROJECT_ROOT / "datasets" / "ml_features.csv"

print("Loading cleaned dataset...")

df = pd.read_csv(INPUT_FILE)

# Separate features and target
X = df.drop(columns=["Label"])

y = df["Label"].astype(str).str.strip().str.upper().map({
    "BENIGN": 0,
    "ATTACK": 1
})

# Convert feature columns to numeric
X = X.apply(pd.to_numeric, errors="coerce")

# Remove rows containing invalid values
valid_rows = X.notna().all(axis=1) & y.notna()

X = X[valid_rows]
y = y[valid_rows]

# Combine features and target
final_df = X.copy()
final_df["Label"] = y

# Save prepared dataset
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
final_df.to_csv(OUTPUT_FILE, index=False)

print("\n" + "=" * 50)
print("FEATURE DATASET CREATED")
print("=" * 50)

print("Feature shape:", X.shape)
print("Target shape:", y.shape)

print("\nTarget distribution:")
print(y.value_counts())

print("\nSaved to:")
print(OUTPUT_FILE)
