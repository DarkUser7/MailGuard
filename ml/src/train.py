"""Train TF-IDF + Logistic Regression with 40K/5K/5K split and leakage checks.

Supports:
  - data/processed/email_dataset_50k.csv (streamed 50K balanced dataset) -> priority
  - fallback: data/raw/email_dataset.csv (small synthetic dataset)

Pipeline:
  1. Load + dedup + clean
  2. Stratified split: 80% train (40K) / 10% val (5K) / 10% test (5K)
  3. Duplicate / leakage check across splits (text overlap = 0 expected)
  4. TF-IDF fit on TRAIN only → transform val/test (no leakage)
  5. Logistic Regression training
  6. Evaluation + save artifacts
"""
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

try:
    from ml.src.preprocessing import load_and_clean_dataset, clean_text
except ImportError:
    from preprocessing import load_and_clean_dataset, clean_text


# Priority order for dataset discovery
CANDIDATE_PATHS = [
    'data/processed/email_dataset_50k.csv',
    'data/raw/email_dataset.csv',
    'data/processed/cleaned_dataset.csv',
]

def _resolve_data_path(explicit: str = None) -> str:
    if explicit and os.path.exists(explicit):
        return explicit
    for p in CANDIDATE_PATHS:
        if os.path.exists(p):
            return p
    return explicit or CANDIDATE_PATHS[0]

def _leakage_check(train_texts, val_texts, test_texts) -> dict:
    train_set = set(train_texts)
    val_set = set(val_texts)
    test_set = set(test_texts)
    train_val = len(train_set & val_set)
    train_test = len(train_set & test_set)
    val_test = len(val_set & test_set)
    return {
        'train_val_overlap': train_val,
        'train_test_overlap': train_test,
        'val_test_overlap': val_test,
        'total_leakage': train_val + train_test + val_test
    }

def train_model(data_path: str = None,
                model_dir: str = 'models'):
    """Train TF-IDF + Logistic Regression spam detector."""
    resolved = _resolve_data_path(data_path)
    print(f"[train] Using dataset: {resolved}")

    # Load and preprocess
    df = load_and_clean_dataset(resolved)

    # Normalize label column: support both string ('ham'/'spam') and int (0/1)
    if 'cleaned_text' not in df.columns:
        raise ValueError("Dataset missing 'cleaned_text' after preprocessing. Check preprocessing.py")

    if df['label'].dtype == object:
        y = (df['label'].astype(str).str.lower() == 'spam').astype(int)
    else:
        y = (df['label'] == 1).astype(int)
        # fallback: if label values are ham/spam strings already numeric mapping failed
        if y.sum() == 0 and (df['label'] == 'spam').any():
            y = (df['label'] == 'spam').astype(int)

    X_text = df['cleaned_text']
    X_raw = df['text']

    print(f"[train] Total after cleaning: {len(df)} | ham={(y==0).sum()} spam={(y==1).sum()}")

    # --- Stratified 40K/5K/5K split (80/10/10) ---
    # Step 1: hold out 10% as TEST
    X_temp_text, X_test_text, y_temp, y_test, X_temp_raw, X_test_raw = train_test_split(
        X_text, y, X_raw, test_size=0.10, random_state=42, stratify=y
    )
    # Step 2: from remaining 90%, hold out 11.11% as VAL (=> 10% of original)
    val_ratio = 0.111111  # 0.10 / 0.90
    X_train_text, X_val_text, y_train, y_val, X_train_raw, X_val_raw = train_test_split(
        X_temp_text, y_temp, X_temp_raw, test_size=val_ratio, random_state=42, stratify=y_temp
    )

    print(f"[train] Split -> train={len(X_train_text)} val={len(X_val_text)} test={len(X_test_text)}")

    # --- Duplicate / leakage check ---
    leakage = _leakage_check(X_train_raw, X_val_raw, X_test_raw)
    print(f"[train] Leakage check: {leakage}")
    if leakage['total_leakage'] > 0:
        print(f"  WARNING: Found {leakage['total_leakage']} duplicate texts across splits! "
              "Consider re-generating splits with deduplication.")

    # Check duplicate within dataset
    dup_count = df.duplicated(subset=['text']).sum()
    print(f"[train] Duplicates in full DF: {dup_count} (should be 0 after preprocessing)")

    # --- TF-IDF : fit ONLY on train ---
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95
    )
    X_train_tfidf = vectorizer.fit_transform(X_train_text)
    X_val_tfidf = vectorizer.transform(X_val_text)
    X_test_tfidf = vectorizer.transform(X_test_text)

    print(f"[train] TF-IDF vocab size: {len(vectorizer.vocabulary_)}")

    # --- Train Logistic Regression ---
    model = LogisticRegression(
        max_iter=1000,
        C=1.0,
        random_state=42
    )
    model.fit(X_train_tfidf, y_train)

    # --- Evaluate ---
    def _eval(name, X_tfidf, y_true):
        y_pred = model.predict(X_tfidf)
        acc = accuracy_score(y_true, y_pred)
        report = classification_report(y_true, y_pred, target_names=['ham', 'spam'], output_dict=True)
        cm = confusion_matrix(y_true, y_pred)
        print(f"\n[{name}] Accuracy: {acc:.4f}")
        print(classification_report(y_true, y_pred, target_names=['ham', 'spam']))
        print(f"Confusion Matrix ({name}):\n{cm}")
        return acc, report, cm, y_pred

    val_acc, val_report, val_cm, _ = _eval("VAL", X_val_tfidf, y_val)
    test_acc, test_report, test_cm, _ = _eval("TEST", X_test_tfidf, y_test)

    # Cross-validation on train only (5-fold)
    cv_scores = cross_val_score(model, X_train_tfidf, y_train, cv=5, scoring='accuracy')
    print(f"\nCV Accuracy (train): {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")

    # --- Save ---
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(model, os.path.join(model_dir, 'spam_model.pkl'))
    joblib.dump(vectorizer, os.path.join(model_dir, 'tfidf_vectorizer.pkl'))

    # Clean tfidf_params to ensure JSON serializability
    clean_params = {}
    for k, v in vectorizer.get_params().items():
        if isinstance(v, (int, float, str, bool, list, tuple, dict)) or v is None:
            clean_params[k] = v
        else:
            clean_params[k] = str(v)

    metrics = {
        'dataset_path': resolved,
        'total_samples': int(len(df)),
        'spam_count': int((y == 1).sum()),
        'ham_count': int((y == 0).sum()),
        'train_size': int(len(X_train_text)),
        'val_size': int(len(X_val_text)),
        'test_size': int(len(X_test_text)),
        'split_ratio': '80/10/10 (train/val/test)',
        'val_accuracy': float(val_acc),
        'test_accuracy': float(test_acc),
        'accuracy': float(test_acc),  # backward compat: primary accuracy = test
        'cv_mean': float(cv_scores.mean()),
        'cv_std': float(cv_scores.std()),
        'val_classification_report': val_report,
        'test_classification_report': test_report,
        'classification_report': test_report,  # backward compat
        'val_confusion_matrix': val_cm.tolist(),
        'test_confusion_matrix': test_cm.tolist(),
        'confusion_matrix': test_cm.tolist(),
        'leakage_check': leakage,
        'tfidf_vocab_size': int(len(vectorizer.vocabulary_)),
        'tfidf_params': clean_params,
    }
    with open(os.path.join(model_dir, 'metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=2, default=str)

    print(f"\nModel saved to {model_dir}/")
    print(f"  - spam_model.pkl")
    print(f"  - tfidf_vectorizer.pkl")
    print(f"  - metrics.json")
    return model, vectorizer, metrics

if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    # Allow CLI: python ml/src/train.py [data_path] [model_dir]
    dp = sys.argv[1] if len(sys.argv) > 1 else None
    md = sys.argv[2] if len(sys.argv) > 2 else 'models'
    train_model(data_path=dp, model_dir=md)
