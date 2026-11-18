import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = PROJECT_ROOT / "datasets" / "cicids2017" / "MachineLearningCVE"
OUTPUT_FILE = PROJECT_ROOT / "datasets" / "ml_dataset.csv"

FILES = [
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

BENIGN_PER_FILE = 20000
ATTACK_PER_FILE = 20000

dataframes = []

for file_name in FILES:

    print(f"\nProcessing: {file_name}")

    file_path = DATASET_DIR / file_name
    if not file_path.is_file():
        raise FileNotFoundError(f"Required CICIDS2017 input file is missing: {file_path}")

    df = pd.read_csv(file_path)

    # Remove extra spaces from column names
    df.columns = df.columns.str.strip()

    # Remove rows with missing labels
    df = df.dropna(subset=["Label"])

    # Separate benign and attack traffic
    benign = df[df["Label"].str.strip().str.upper() == "BENIGN"]

    attack = df[df["Label"].str.strip().str.upper() != "BENIGN"]

    print("Total rows:", len(df))
    print("Benign rows:", len(benign))
    print("Attack rows:", len(attack))

    # Sample available rows
    benign_sample = benign.sample(
        n=min(BENIGN_PER_FILE, len(benign)),
        random_state=42
    )

    attack_sample = attack.sample(
        n=min(ATTACK_PER_FILE, len(attack)),
        random_state=42
    )

    dataframes.append(benign_sample)
    dataframes.append(attack_sample)


# Combine selected data
final_df = pd.concat(dataframes, ignore_index=True)

# Convert labels into binary classification
final_df["Label"] = final_df["Label"].apply(
    lambda x: "BENIGN"
    if str(x).strip().upper() == "BENIGN"
    else "ATTACK"
)

# Shuffle the dataset
final_df = final_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
# Save dataset
final_df.to_csv(OUTPUT_FILE, index=False)

print("\n" + "=" * 60)
print("DATASET CREATED")
print("=" * 60)

print("Rows:", len(final_df))
print("Columns:", len(final_df.columns))

print("\nLabel distribution:")
print(final_df["Label"].value_counts())

print("\nSaved to:")
print(OUTPUT_FILE)
