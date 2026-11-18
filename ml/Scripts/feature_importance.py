import pandas as pd
import joblib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_FILE = PROJECT_ROOT / "ml" / "models" / "threat_detector.pkl"
DATA_FILE = PROJECT_ROOT / "datasets" / "ml_features.csv"

print("Loading model...")

model = joblib.load(MODEL_FILE)

df = pd.read_csv(DATA_FILE)

X = df.drop(columns=["Label"])

# Get feature importance
importance = model.feature_importances_
if len(importance) != len(X.columns):
    raise ValueError(f"Model has {len(importance)} features but dataset has {len(X.columns)} columns")

feature_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": importance
})

# Sort from highest to lowest
feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print("\n" + "=" * 60)
print("TOP 15 IMPORTANT FEATURES")
print("=" * 60)

print(
    feature_importance.head(15).to_string(index=False)
)

# Save results
feature_importance.to_csv(
    PROJECT_ROOT / "ml" / "models" / "feature_importance.csv",
    index=False
)

print("\nFeature importance saved to:")
print("ml/models/feature_importance.csv")
