import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_FILE = PROJECT_ROOT / "datasets" / "ml_features.csv"
OUTPUT_FILE = PROJECT_ROOT / "ml" / "models" / "feature_names.txt"

print("Loading feature dataset...")

df = pd.read_csv(INPUT_FILE)

# Get feature names without the target column
features = df.drop(columns=["Label"]).columns

# Make sure models directory exists
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

# Save feature names
with OUTPUT_FILE.open("w", encoding="utf-8", newline="\n") as f:
    for feature in features:
        f.write(feature + "\n")

print("\nFeature names saved successfully.")
print("Total features:", len(features))
print("Saved to:", OUTPUT_FILE)
