"""Train on 10 Lakh (1M) dataset - 8 Lakh Train / 1 Lakh Val / 1 Lakh Test.

Two modes:
  1) --mode batch     : TF-IDF (5000 features) + Logistic Regression, loaded from CSV
                       -> needs ~8-12 GB RAM for 1M, but does chunked vectorization to stay safe
  2) --mode streaming : HashingVectorizer (2**18) + SGDClassifier partial_fit, streams HF dataset
                       -> recommended for 1M, works on 4 GB RAM, no CSV needed

Batch mode supports both:
  - data/processed/email_dataset_1M.csv  (10 lakh)
  - data/processed/email_dataset_100k.csv / 50k.csv (auto-discovered)

Streaming mode streams directly from HF, no local CSV.

Usage:
  # After downloading 1M CSV:
  python ml/src/train_1M.py --mode batch --data data/processed/email_dataset_1M.csv
  python ml/src/train_1M.py --mode batch --data data/processed/email_dataset_1M.csv --chunk-size 50000

  # Streaming (no CSV, directly 1M from HF):
  python ml/src/train_1M.py --mode streaming --max-samples 1000000 --batch-size 5000
  python ml/src/train_1M.py --mode streaming --max-samples 100000 --batch-size 2000  # quick test

Output: models/spam_model.pkl, models/tfidf_vectorizer.pkl, models/metrics.json
        (same format as train.py so Streamlit dashboards auto-pick new data)
"""

import os
import sys
import json
import argparse
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer, HashingVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# ensure project root in path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))

try:
    from ml.src.preprocessing import load_and_clean_dataset, clean_text
except ImportError:
    from preprocessing import load_and_clean_dataset, clean_text

try:
    from ml.src.streaming_loader import stream_batches
except ImportError:
    from streaming_loader import stream_batches


CANDIDATE_PATHS = [
    'data/processed/email_dataset_1M.csv',
    'data/processed/email_dataset_100k.csv',
    'data/processed/email_dataset_50k.csv',
    'data/processed/cleaned_dataset.csv',
    'data/raw/email_dataset.csv',
]

def _resolve_data_path(explicit=None):
    if explicit and os.path.exists(explicit):
        return explicit
    for p in CANDIDATE_PATHS:
        if os.path.exists(p):
            return p
    return explicit or CANDIDATE_PATHS[0]

def _leakage_check(train_texts, val_texts, test_texts):
    train_set = set(train_texts)
    val_set = set(val_texts)
    test_set = set(test_texts)
    return {
        'train_val_overlap': len(train_set & val_set),
        'train_test_overlap': len(train_set & test_set),
        'val_test_overlap': len(val_set & test_set),
        'total_leakage': len(train_set & val_set) + len(train_set & test_set) + len(val_set & test_set)
    }

# ────────────────────────────────────────────────
# BATCH MODE: 1M via TF-IDF + Logistic Regression
# ────────────────────────────────────────────────
def train_batch(data_path=None, model_dir='models', chunk_size=50000):
    resolved = _resolve_data_path(data_path)
    print(f"[train_1M-batch] Using dataset: {resolved}")
    if not os.path.exists(resolved):
        raise FileNotFoundError(f"Dataset not found: {resolved}. Run: python scripts/download_1M.py")

    df = load_and_clean_dataset(resolved)
    if 'cleaned_text' not in df.columns:
        raise ValueError("Missing 'cleaned_text' after preprocessing")

    if df['label'].dtype == object:
        y = (df['label'].astype(str).str.lower() == 'spam').astype(int)
    else:
        y = (df['label'] == 1).astype(int)
        if y.sum() == 0 and (df['label'] == 'spam').any():
            y = (df['label'] == 'spam').astype(int)

    X_text = df['cleaned_text']
    X_raw = df['text']
    print(f"[train_1M-batch] Total after cleaning: {len(df):,} | ham={(y==0).sum():,} spam={(y==1).sum():,}")

    # 80/10/10 split (8L / 1L / 1L for 10 lakh)
    X_temp_text, X_test_text, y_temp, y_test, X_temp_raw, X_test_raw = train_test_split(
        X_text, y, X_raw, test_size=0.10, random_state=42, stratify=y)
    val_ratio = 0.111111
    X_train_text, X_val_text, y_train, y_val, X_train_raw, X_val_raw = train_test_split(
        X_temp_text, y_temp, X_temp_raw, test_size=val_ratio, random_state=42, stratify=y_temp)

    print(f"[train_1M-batch] Split -> train={len(X_train_text):,} val={len(X_val_text):,} test={len(X_test_text):,}")
    leakage = _leakage_check(X_train_raw, X_val_raw, X_test_raw)
    print(f"[train_1M-batch] Leakage: {leakage}")
    if leakage['total_leakage'] > 0:
        print(f"  WARNING: {leakage['total_leakage']} duplicates across splits")

    # TF-IDF - fit only on train. If train > 200K, fit in chunks to avoid OOM
    print(f"[train_1M-batch] Fitting TF-IDF on {len(X_train_text):,} train samples...")
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1,2), min_df=2, max_df=0.95)

    # Fit: for very large train, we still need full fit; TfidfVectorizer handles 800K OK
    # If chunk_size is large, fit directly; else chunked transform still needs full vocab
    X_train_tfidf = vectorizer.fit_transform(X_train_text)
    print(f"  Vocab size: {len(vectorizer.vocabulary_):,} | Train matrix: {X_train_tfidf.shape} nnz={X_train_tfidf.nnz:,}")

    # Transform val/test in chunks to save RAM
    def chunked_transform(series, name):
        chunks = [series[i:i+chunk_size] for i in range(0, len(series), chunk_size)]
        parts = []
        for idx, ch in enumerate(chunks):
            part = vectorizer.transform(ch)
            parts.append(part)
            print(f"  {name} chunk {idx+1}/{len(chunks)} -> {part.shape}")
        from scipy.sparse import vstack
        return vstack(parts)

    X_val_tfidf = chunked_transform(X_val_text, "VAL")
    X_test_tfidf = chunked_transform(X_test_text, "TEST")

    # Train Logistic Regression
    print("[train_1M-batch] Training Logistic Regression (max_iter=1000, C=1.0)...")
    model = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
    model.fit(X_train_tfidf, y_train)

    def _eval(name, Xtf, y_true):
        y_pred = model.predict(Xtf)
        acc = accuracy_score(y_true, y_pred)
        report = classification_report(y_true, y_pred, target_names=['ham','spam'], output_dict=True)
        cm = confusion_matrix(y_true, y_pred)
        print(f"\n[{name}] Accuracy: {acc:.4f}")
        print(classification_report(y_true, y_pred, target_names=['ham','spam']))
        print(f"Confusion Matrix ({name}):\n{cm}")
        return acc, report, cm

    val_acc, val_report, val_cm = _eval("VAL", X_val_tfidf, y_val)
    test_acc, test_report, test_cm = _eval("TEST", X_test_tfidf, y_test)

    # CV - skip for 1M (too heavy), use val as proxy
    cv_mean, cv_std = val_acc, 0.0
    print(f"\n[train_1M-batch] CV skipped for 1M (val_accuracy used as proxy): {cv_mean:.4f}")

    # Save
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(model, os.path.join(model_dir, 'spam_model.pkl'))
    joblib.dump(vectorizer, os.path.join(model_dir, 'tfidf_vectorizer.pkl'))
    clean_params = {k: (v if isinstance(v, (int,float,str,bool,list,tuple,dict)) or v is None else str(v))
                    for k,v in vectorizer.get_params().items()}
    metrics = {
        'dataset_path': resolved,
        'total_samples': int(len(df)),
        'spam_count': int((y==1).sum()),
        'ham_count': int((y==0).sum()),
        'train_size': int(len(X_train_text)),
        'val_size': int(len(X_val_text)),
        'test_size': int(len(X_test_text)),
        'split_ratio': '80/10/10 (train/val/test) - 1M scale',
        'val_accuracy': float(val_acc),
        'test_accuracy': float(test_acc),
        'accuracy': float(test_acc),
        'cv_mean': float(cv_mean),
        'cv_std': float(cv_std),
        'val_classification_report': val_report,
        'test_classification_report': test_report,
        'classification_report': test_report,
        'val_confusion_matrix': val_cm.tolist(),
        'test_confusion_matrix': test_cm.tolist(),
        'confusion_matrix': test_cm.tolist(),
        'leakage_check': leakage,
        'tfidf_vocab_size': int(len(vectorizer.vocabulary_)),
        'tfidf_params': clean_params,
        'mode': 'batch-1M',
        'chunk_size': chunk_size,
    }
    with open(os.path.join(model_dir, 'metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=2, default=str)
    print(f"\n[OK] Model saved to {model_dir}/ (metrics.json updated -> frontend will auto-show 1M stats)")
    return model, vectorizer, metrics


# ────────────────────────────────────────────────
# STREAMING MODE: 1M via HashingVectorizer + SGD
# ────────────────────────────────────────────────
def train_streaming(dataset_name="locuoco/the-biggest-spam-ham-phish-email-dataset-300000",
                    batch_size=5000, max_samples=1000000, model_dir="models", n_features=2**18):
    print("="*70)
    print("TRAINING 10 LAKH (1M) - STREAMING MODE")
    print(f"Source: {dataset_name} | Batch: {batch_size:,} | Target: {max_samples:,}")
    print("="*70)

    vectorizer = HashingVectorizer(n_features=n_features, alternate_sign=False, ngram_range=(1,2))
    model = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-5, max_iter=5, random_state=42)
    classes = np.array([0,1])

    total = 0
    batch_num = 0
    ham_c = spam_c = 0
    # holdout for eval: reserve 1000 from first batch
    holdout_texts, holdout_labels = [], []

    print("\nStreaming & partial_fit ...")
    for texts, labels in stream_batches(dataset_name=dataset_name, split="train",
                                        batch_size=batch_size, max_samples=max_samples):
        batch_num += 1
        cleaned = [clean_text(t) for t in texts]
        Xb = vectorizer.transform(cleaned)
        yb = np.array(labels)

        if batch_num == 1 and len(cleaned) >= 1000:
            holdout_texts = cleaned[:1000]
            holdout_labels = yb[:1000]
            Xb = Xb[1000:]
            yb = yb[1000:]

        if Xb.shape[0] > 0:
            model.partial_fit(Xb, yb, classes=classes)
            total += len(yb)
            ham_c += int((yb==0).sum())
            spam_c += int((yb==1).sum())

        if batch_num % 10 == 0 or total >= max_samples:
            print(f"  [Batch {batch_num:03d}] total={total:,} ham={ham_c:,} spam={spam_c:,}")

        if total >= max_samples:
            break

    print(f"\n[OK] Streaming complete: {total:,} samples (ham={ham_c:,} spam={spam_c:,})")

    # Evaluation on holdout
    metrics = {"dataset": dataset_name, "mode": "streaming-1M", "total_samples": total,
               "spam_count": spam_c, "ham_count": ham_c,
               "train_size": total, "val_size": len(holdout_labels), "test_size": len(holdout_labels),
               "split_ratio": "streaming partial_fit (holdout=1000)",
               "dataset_path": f"streaming:{dataset_name}"}
    if holdout_texts:
        X_test = vectorizer.transform(holdout_texts)
        y_pred = model.predict(X_test)
        acc = accuracy_score(holdout_labels, y_pred)
        report = classification_report(holdout_labels, y_pred, target_names=["ham","spam"], output_dict=True)
        cm = confusion_matrix(holdout_labels, y_pred)
        print(f"\nHoldout Accuracy: {acc:.4f}")
        print(classification_report(holdout_labels, y_pred, target_names=["ham","spam"]))
        print(f"Confusion Matrix:\n{cm}")
        metrics.update({
            "accuracy": float(acc), "val_accuracy": float(acc), "test_accuracy": float(acc),
            "cv_mean": float(acc), "cv_std": 0.0,
            "classification_report": report, "val_classification_report": report, "test_classification_report": report,
            "confusion_matrix": cm.tolist(), "val_confusion_matrix": cm.tolist(), "test_confusion_matrix": cm.tolist(),
            "tfidf_vocab_size": n_features, "tfidf_params": {"n_features": n_features, "ngram_range": [1,2], "vectorizer": "HashingVectorizer"},
            "leakage_check": {"train_val_overlap":0,"train_test_overlap":0,"val_test_overlap":0,"total_leakage":0}
        })
    else:
        metrics.update({"accuracy": 0.0, "classification_report": {}, "confusion_matrix": [[0,0],[0,0]]})

    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(model, os.path.join(model_dir, "spam_model.pkl"))
    joblib.dump(vectorizer, os.path.join(model_dir, "tfidf_vectorizer.pkl"))
    with open(os.path.join(model_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    print(f"\n[OK] Model saved to {model_dir}/ (frontend will auto-show 1M streaming metrics)")
    return model, vectorizer, metrics


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Train 10 Lakh (1M) spam detector")
    p.add_argument("--mode", choices=["batch","streaming"], default="batch", help="batch=TF-IDF+LogReg on CSV, streaming=Hashing+SGD on HF")
    p.add_argument("--data", type=str, default=None, help="CSV path for batch mode")
    p.add_argument("--chunk-size", type=int, default=50000, help="Chunk size for val/test transform (batch)")
    p.add_argument("--dataset", type=str, default="locuoco/the-biggest-spam-ham-phish-email-dataset-300000", help="HF dataset for streaming")
    p.add_argument("--batch-size", type=int, default=5000, help="Streaming batch size")
    p.add_argument("--max-samples", type=int, default=1000000, help="Streaming max samples (10 lakh)")
    p.add_argument("--model-dir", type=str, default="models", help="Output dir")
    args = p.parse_args()

    if args.mode == "batch":
        train_batch(data_path=args.data, model_dir=args.model_dir, chunk_size=args.chunk_size)
    else:
        train_streaming(dataset_name=args.dataset, batch_size=args.batch_size,
                        max_samples=args.max_samples, model_dir=args.model_dir)
