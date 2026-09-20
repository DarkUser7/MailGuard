"""Download 100K balanced dataset (50K ham + 50K spam) via Hugging Face streaming.

Streams locuoco/the-biggest-spam-ham-phish-email-dataset-300000 (365K)
and saves balanced 100K CSV to data/processed/email_dataset_100k.csv
Uses streaming=True so full dataset is never materialized locally.

Usage:
  python scripts/download_100k.py
  python scripts/download_100k.py --ham 50000 --spam 50000 --output data/processed/email_dataset_100k.csv
"""

import os
import argparse
from datasets import load_dataset
import pandas as pd

DATASET_NAME = "locuoco/the-biggest-spam-ham-phish-email-dataset-300000"
DEFAULT_HAM = 50000
DEFAULT_SPAM = 50000
DEFAULT_OUTPUT = "data/processed/email_dataset_100k.csv"

def parse_args():
    p = argparse.ArgumentParser(description="Download 100K balanced spam/ham dataset (streaming, no hardcoded data)")
    p.add_argument("--ham", type=int, default=DEFAULT_HAM, help="Target ham count (default 50000)")
    p.add_argument("--spam", type=int, default=DEFAULT_SPAM, help="Target spam count (default 50000)")
    p.add_argument("--output", type=str, default=DEFAULT_OUTPUT, help="Output CSV path")
    p.add_argument("--dataset", type=str, default=DATASET_NAME, help="HF dataset name")
    return p.parse_args()

def main():
    args = parse_args()
    target_ham = args.ham
    target_spam = args.spam
    output_path = args.output
    dataset_name = args.dataset

    print("="*60)
    print(f"Downloading {target_ham + target_spam} balanced dataset")
    print(f"Target: ham={target_ham} spam={target_spam}")
    print(f"Source: {dataset_name} (streaming)")
    print(f"Output: {output_path}")
    print("="*60)

    ham = []
    spam = []

    print("\nConnecting to Hugging Face...")
    dataset = load_dataset(dataset_name, split="train", streaming=True)
    print("Streaming dataset... (press Ctrl+C to abort)")

    count = 0
    for row in dataset:
        text = row.get("text")
        label = row.get("label")

        if not text or not text.strip():
            continue

        # 0 = Ham
        if label == 0 and len(ham) < target_ham:
            ham.append({"text": text, "label": "ham"})
        # 1 = Phish, 2 = Spam -> both treated as spam
        elif label in [1, 2] and len(spam) < target_spam:
            spam.append({"text": text, "label": "spam"})

        count += 1
        if count % 10000 == 0:
            print(f"  streamed {count} rows | collected ham={len(ham)}/{target_ham} spam={len(spam)}/{target_spam}")

        if len(ham) >= target_ham and len(spam) >= target_spam:
            break

    df = pd.DataFrame(ham + spam)

    print("\nBefore duplicate removal:")
    print(df["label"].value_counts())
    print("Total:", len(df))

    # Critical: dedup + empty removal (same as train.py preprocessing)
    df = df.drop_duplicates(subset=["text"])
    df = df[df["text"].str.strip().astype(bool)]

    print("\nAfter cleaning (dedup):")
    print(df["label"].value_counts())
    print("Total:", len(df))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)

    print(f"\n✓ Dataset saved to: {output_path} (requested ham={target_ham} spam={target_spam}, actual={len(df)})")
    print("Next step: python ml/src/train.py data/processed/email_dataset_100k.csv")
    print("All dashboards will auto-pick new data via models/metrics.json")

if __name__ == "__main__":
    main()
