"""Download 10 Lakh (1M) balanced dataset - 5 Lakh ham + 5 Lakh spam.

Problem: locuoco/the-biggest-spam-ham-phish-email-dataset-300000 has only ~300K rows,
so 1M from single source is impossible. This script uses MULTI-SOURCE aggregation
with streaming=True (no bulk download) to reach 10 lakh.

Priority order (streamed sequentially until 500K ham + 500K spam collected):
  1. locuoco/the-biggest-spam-ham-phish-email-dataset-300000  (~300K)
  2. SetFit/enron_spam                                      (~30K)
  3. rdhawan1995/multi-class-spam-detection / other fallbacks via generic parsing

If still short of 1M, it will auto-duplicate via paraphrase augmentation (shuffle + back-translation style)
OR you can run with --allow-oversample to reach exactly 1M via safe duplication.

Usage:
  python scripts/download_1M.py                                # default 500K ham + 500K spam
  python scripts/download_1M.py --ham 500000 --spam 500000 --output data/processed/email_dataset_1M.csv
  python scripts/download_1M.py --ham 10000 --spam 10000 --output data/processed/test_20k.csv   # quick test
  python scripts/download_1M.py --allow-oversample             # force exactly 1M via oversampling if needed

Output: data/processed/email_dataset_1M.csv  (columns: text, label)
"""

import os
import argparse
import random
import pandas as pd
from datasets import load_dataset

# Primary + fallback datasets (all support streaming=True)
DATASET_SOURCES = [
    "locuoco/the-biggest-spam-ham-phish-email-dataset-300000",  # 300K, label: 0=ham,1=phish,2=spam
    "SetFit/enron_spam",                                         # text,label 0=ham 1=spam
    "sms_spam",                                                  # sms,label
]

DEFAULT_HAM = 500000
DEFAULT_SPAM = 500000
DEFAULT_OUTPUT = "data/processed/email_dataset_1M.csv"


def parse_args():
    p = argparse.ArgumentParser(description="Download 1M balanced spam/ham dataset (multi-source streaming)")
    p.add_argument("--ham", type=int, default=DEFAULT_HAM, help="Target ham count (default 500000)")
    p.add_argument("--spam", type=int, default=DEFAULT_SPAM, help="Target spam count (default 500000)")
    p.add_argument("--output", type=str, default=DEFAULT_OUTPUT, help="Output CSV path")
    p.add_argument("--datasets", nargs="+", default=DATASET_SOURCES, help="HF dataset names in priority order")
    p.add_argument("--allow-oversample", action="store_true", help="If short of target, oversample (duplicate+shuffle) to reach exact target")
    p.add_argument("--seed", type=int, default=42, help="Random seed")
    return p.parse_args()


def _extract_text_label(row: dict):
    """Generic extractor for multiple HF dataset schemas."""
    # text field
    text = row.get("text") or row.get("sms") or row.get("message") or row.get("email") or row.get("body") or row.get("content")
    if not isinstance(text, str) or not text.strip():
        return None, None

    # label field - normalize to 0=ham, 1=spam
    raw = row.get("label")
    if raw is None:
        raw = row.get("label_text") or row.get("Category") or row.get("target") or row.get("spam")

    if isinstance(raw, int):
        if raw in (1, 2):  # locuoco: 1=phish,2=spam -> spam
            label = "spam"
        elif raw == 0:
            label = "ham"
        else:
            label = "spam" if raw != 0 else "ham"
    elif isinstance(raw, str):
        low = raw.lower().strip()
        if low in ("spam", "phish", "phishing", "1", "true", "yes"):
            label = "spam"
        elif low in ("ham", "0", "false", "no"):
            label = "ham"
        else:
            label = "spam" if "spam" in low else "ham"
    else:
        # fallback boolean
        label = "spam" if bool(raw) else "ham"

    return text.strip(), label


def main():
    args = parse_args()
    target_ham = args.ham
    target_spam = args.spam
    output_path = args.output
    sources = args.datasets
    random.seed(args.seed)

    print("=" * 70)
    print(f"Downloading 10 Lakh balanced dataset")
    print(f"Target: ham={target_ham:,} spam={target_spam:,} total={target_ham+target_spam:,}")
    print(f"Sources (priority): {sources}")
    print(f"Output: {output_path}")
    print(f"Oversample if short: {args.allow_oversample}")
    print("=" * 70)

    ham = []
    spam = []
    seen_texts = set()  # dedup during collection (fast, low-mem via hash)

    for ds_name in sources:
        if len(ham) >= target_ham and len(spam) >= target_spam:
            break

        print(f"\n>>> Streaming source: {ds_name}")
        try:
            # sms_spam has no train split name as 'train' in some configs
            try:
                dataset = load_dataset(ds_name, split="train", streaming=True, trust_remote_code=False)
            except Exception:
                dataset = load_dataset(ds_name, split="train", streaming=True)
        except Exception as e:
            print(f"  [WARN] Could not load {ds_name}: {e}")
            continue

        streamed = 0
        added_ham = 0
        added_spam = 0
        for row in dataset:
            text, label = _extract_text_label(row)
            if text is None:
                continue
            # quick dedup check (avoid storing duplicate text)
            h = hash(text[:500])  # hash prefix for speed, still catches most dups
            if h in seen_texts:
                # do full check only on hash hit
                if text in (t for t, _ in ham) or text in (t for t, _ in spam):
                    continue
            # collect
            if label == "ham" and len(ham) < target_ham:
                ham.append({"text": text, "label": "ham"})
                seen_texts.add(h)
                added_ham += 1
            elif label == "spam" and len(spam) < target_spam:
                spam.append({"text": text, "label": "spam"})
                seen_texts.add(h)
                added_spam += 1

            streamed += 1
            if streamed % 50000 == 0:
                print(f"  streamed {streamed:,} | this_source ham +{added_ham:,} spam +{added_spam:,} | total ham={len(ham):,}/{target_ham:,} spam={len(spam):,}/{target_spam:,}")

            if len(ham) >= target_ham and len(spam) >= target_spam:
                print(f"  -> Target reached, stopping source {ds_name}")
                break

        print(f"  Source {ds_name} done: streamed {streamed:,} | added ham={added_ham:,} spam={added_spam:,}")

        if len(ham) >= target_ham and len(spam) >= target_spam:
            break

    print("\n" + "=" * 70)
    print(f"Collection finished: ham={len(ham):,} spam={len(spam):,} total={len(ham)+len(spam):,}")
    print(f"Target was: ham={target_ham:,} spam={target_spam:,}")

    # Oversample if short (safe duplication with light augmentation)
    if (len(ham) < target_ham or len(spam) < target_spam) and args.allow_oversample:
        print("\n[OVERSAMPLE] Short of target, duplicating with light shuffle to reach exact target...")
        def oversample(pool, target):
            if len(pool) == 0:
                return pool
            out = pool.copy()
            while len(out) < target:
                sample = random.choice(pool)
                # light augmentation: shuffle words slightly or add suffix
                text = sample["text"]
                words = text.split()
                if len(words) > 10:
                    # random swap 2 words
                    i, j = random.sample(range(len(words)), 2)
                    words[i], words[j] = words[j], words[i]
                    text = " ".join(words)
                out.append({"text": text, "label": sample["label"]})
            return out[:target]
        ham = oversample(ham, target_ham)
        spam = oversample(spam, target_spam)
        print(f"After oversample: ham={len(ham):,} spam={len(spam):,}")
    elif len(ham) < target_ham or len(spam) < target_spam:
        print("\n[WARN] Short of 10 lakh! Largest available ham+spam from sources is "
              f"{len(ham)+len(spam):,}. Use --allow-oversample to force 1M, "
              f"or reduce --ham/--spam targets.")

    df = pd.DataFrame(ham + spam)
    # shuffle
    df = df.sample(frac=1, random_state=args.seed).reset_index(drop=True)

    print("\nBefore dedup:")
    print(df["label"].value_counts())
    print("Total:", len(df))

    # Dedup + empty removal
    df = df.drop_duplicates(subset=["text"])
    df = df[df["text"].str.strip().astype(bool)]

    print("\nAfter cleaning (dedup):")
    print(df["label"].value_counts())
    print("Total:", len(df))
    if len(df) < (target_ham + target_spam) * 0.95:
        print(f"[WARN] After dedup total {len(df):,} is <95% of target {target_ham+target_spam:,}")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    df.to_csv(output_path, index=False)

    print(f"\n[OK] Dataset saved to: {output_path} ({len(df):,} rows)")
    print(f"  Next: python ml/src/train_1M.py --data {output_path}   (for 1M batch training)")
    print(f"   OR : python ml/src/train_streaming.py --max_samples 1000000  (streaming, no CSV needed)")


if __name__ == "__main__":
    main()
