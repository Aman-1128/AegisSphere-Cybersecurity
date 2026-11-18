import pandas as pd
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_FILE = PROJECT_ROOT / "datasets" / "ml_dataset.csv"
OUTPUT_FILE = PROJECT_ROOT / "datasets" / "ml_dataset_clean.csv"

print("Loading dataset...")

df = pd.read_csv(INPUT_FILE)

# Remove extra spaces from column names
df.columns = df.columns.str.strip()

print("Original shape:", df.shape)

# Remove infinite values
df = df.replace([np.inf, -np.inf], np.nan)

# Count missing values
missing_before = df.isnull().sum().sum()

print("Missing/invalid values before cleaning:", missing_before)

# Remove rows containing missing values
df = df.dropna()

print("Rows after cleaning:", len(df))

# Make sure labels are clean
df["Label"] = df["Label"].astype(str).str.strip()

# Shuffle dataset
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Save cleaned dataset
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(OUTPUT_FILE, index=False)

print("\n" + "=" * 50)
print("CLEAN DATASET CREATED")
print("=" * 50)

print("Final shape:", df.shape)

print("\nLabel distribution:")
print(df["Label"].value_counts())

print("\nRemaining missing values:", df.isnull().sum().sum())

print("\nSaved to:")
print(OUTPUT_FILE)
