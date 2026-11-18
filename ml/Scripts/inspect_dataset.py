import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = PROJECT_ROOT / "datasets" / "cicids2017" / "MachineLearningCVE"

files = [
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

for file_name in files:
    file_path = DATASET_DIR / file_name

    if not file_path.is_file():
        print(f"Skipping missing dataset file: {file_path}")
        continue

    print("\n" + "=" * 70)
    print(f"FILE: {file_name}")
    print("=" * 70)

    # Read only a small sample first
    df = pd.read_csv(file_path, nrows=5000)

    print("Sample rows:", len(df))
    print("Number of columns:", len(df.columns))

    print("\nColumns:")
    for column in df.columns:
        print("-", column)

    print("\nLabel distribution in sample:")

    label_column = df.columns[-1]

    print("Label column:", label_column)
    print(df[label_column].value_counts())
