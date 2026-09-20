"""Download 50K balanced dataset via Hugging Face streaming (no raw bulk download).

Streams locuoco/the-biggest-spam-ham-phish-email-dataset-300000 (365K)
and saves a balanced 25K ham + 25K spam (=50K) CSV to data/processed.
Uses streaming=True so full dataset is never materialized locally.
"""

import os
import argparse
from datasets import load_dataset
import pandas as pd

DATASET_NAME = "locuoco/the-biggest-spam-ham-phish-email-dataset-300000"

# Defaults — override via CLI args so no hardcoded limit blocks future larger datasets
DEFAULT_TARGET_HAM = 25000
DEFAULT_TARGET_SPAM = 25000

def _parse_args():
    p = argparse.ArgumentParser(description="Stream balanced ham/spam CSV from Hugging Face (no hardcoded data)")
    p.add_argument("--ham", type=int, default=DEFAULT_TARGET_HAM, help="Target ham count (default 25000)")
    p.add_argument("--spam", type=int, default=DEFAULT_TARGET_SPAM, help="Target spam count (default 25000)")
    p.add_argument("--output", type=str, default="data/processed/email_dataset_50k.csv", help="Output CSV path")
    p.add_argument("--dataset", type=str, default=DATASET_NAME, help="HF dataset name")
    args, _ = p.parse_known_args()
    return args

_args = _parse_args()
DATASET_NAME = _args.dataset
TARGET_HAM = _args.ham
TARGET_SPAM = _args.spam
OUTPUT_PATH = _args.output

ham = []
spam = []

print("Connecting to Hugging Face...")

dataset = load_dataset(
    DATASET_NAME,
    split="train",
    streaming=True
)

print("Streaming dataset...")

for row in dataset:

    text = row.get("text")
    label = row.get("label")

    if not text or not text.strip():
        continue

    # 0 = Ham
    if label == 0 and len(ham) < TARGET_HAM:
        ham.append({
            "text": text,
            "label": "ham"
        })

    # 1 = Phish, 2 = Spam -> both treated as spam
    elif label in [1, 2] and len(spam) < TARGET_SPAM:
        spam.append({
            "text": text,
            "label": "spam"
        })

    if len(ham) >= TARGET_HAM and len(spam) >= TARGET_SPAM:
        break


df = pd.DataFrame(ham + spam)

print("\nBefore duplicate removal:")
print(df["label"].value_counts())
print("Total:", len(df))


# Remove duplicate emails (critical for leakage-free evaluation)
df = df.drop_duplicates(subset=["text"])

# Remove empty emails
df = df[df["text"].str.strip().astype(bool)]


print("\nAfter cleaning:")
print(df["label"].value_counts())
print("Total:", len(df))


output_path = OUTPUT_PATH
os.makedirs(os.path.dirname(output_path), exist_ok=True)

df.to_csv(
    output_path,
    index=False
)

print(f"\nDataset saved to: {output_path} (requested ham={TARGET_HAM} spam={TARGET_SPAM})")
print("Note: total may be < requested after dedup — expected and correct. Re-run train.py and all dashboards will pick up the new file via metrics.json.")
