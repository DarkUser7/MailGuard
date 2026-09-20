"""Incremental / Streaming Model Training for Large Datasets.

Uses Hugging Face Streaming + HashingVectorizer + SGDClassifier (partial_fit)
to train spam detection models without downloading raw data locally.
"""

import os
import sys
import json
import joblib
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, classification_report

# Ensure imports work from any path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))

try:
    from ml.src.streaming_loader import stream_batches
    from ml.src.preprocessing import clean_text
except ImportError:
    from streaming_loader import stream_batches
    from preprocessing import clean_text


def train_streaming_model(
    dataset_name: str = "locuoco/the-biggest-spam-ham-phish-email-dataset-300000",
    batch_size: int = 1000,
    max_samples: int = 50000,
    model_dir: str = "models",
    n_features: int = 2**18
):
    """Train an out-of-core spam classifier using streaming data.
    
    Args:
        dataset_name: Hugging Face dataset identifier.
        batch_size: Number of samples per batch streamed.
        max_samples: Maximum number of samples to process.
        model_dir: Directory where the trained model artifacts will be saved.
        n_features: Number of features for HashingVectorizer.
    """
    print("=" * 60)
    print("STARTING STREAMING MODEL TRAINING")
    print(f"Source Dataset : {dataset_name} (Hugging Face Streaming)")
    print(f"Batch Size     : {batch_size}")
    print(f"Target Samples : {max_samples}")
    print("=" * 60)

    # 1. Stateless HashingVectorizer (No memory overhead for vocabulary)
    vectorizer = HashingVectorizer(
        n_features=n_features,
        alternate_sign=False,
        ngram_range=(1, 2)
    )

    # 2. Incremental SGD Classifier (Equivalent to Logistic Regression with log_loss)
    model = SGDClassifier(
        loss="log_loss",
        penalty="l2",
        alpha=1e-5,
        max_iter=5,
        random_state=42
    )

    classes = np.array([0, 1])
    total_samples = 0
    batch_num = 0

    holdout_texts = []
    holdout_labels = []

    print("\nStreaming data and training incrementally...")
    
    for texts, labels in stream_batches(
        dataset_name=dataset_name,
        split="train",
        batch_size=batch_size,
        max_samples=max_samples
    ):
        batch_num += 1
        
        # Clean batch texts
        cleaned_batch = [clean_text(t) for t in texts]
        
        # Vectorize batch
        X_batch = vectorizer.transform(cleaned_batch)
        y_batch = np.array(labels)
        
        # Save first batch for evaluation holdout
        if batch_num == 1 and len(texts) >= 200:
            holdout_texts = cleaned_batch[:200]
            holdout_labels = y_batch[:200]
            X_batch = X_batch[200:]
            y_batch = y_batch[200:]

        if X_batch.shape[0] > 0:
            model.partial_fit(X_batch, y_batch, classes=classes)
            total_samples += len(y_batch)
            
        print(f"  [Batch {batch_num:03d}] Processed {total_samples} samples | Spam: {(y_batch == 1).sum()} | Ham: {(y_batch == 0).sum()}")

    print("\n" + "=" * 60)
    print(f"STREAMING TRAINING COMPLETE: {total_samples} samples processed")
    print("=" * 60)

    # Evaluation on holdout set
    metrics = {
        "dataset": dataset_name,
        "mode": "streaming",
        "total_samples": total_samples
    }

    if holdout_texts:
        X_test = vectorizer.transform(holdout_texts)
        y_pred = model.predict(X_test)
        acc = accuracy_score(holdout_labels, y_pred)
        report = classification_report(holdout_labels, y_pred, target_names=["ham", "spam"], output_dict=True)
        
        print(f"\nHoldout Test Accuracy: {acc:.4f}")
        print("\nClassification Report:")
        print(classification_report(holdout_labels, y_pred, target_names=["ham", "spam"]))
        
        metrics["accuracy"] = float(acc)
        metrics["classification_report"] = report

    # Save model and vectorizer
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "spam_model.pkl")
    vec_path = os.path.join(model_dir, "tfidf_vectorizer.pkl")
    metrics_path = os.path.join(model_dir, "metrics.json")

    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vec_path)
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel & Vectorizer saved to '{model_dir}/'")
    print(f"   - {model_path}")
    print(f"   - {vec_path}")
    return model, vectorizer, metrics


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train spam detector with Hugging Face streaming.")
    parser.add_argument("--dataset", type=str, default="locuoco/the-biggest-spam-ham-phish-email-dataset-300000", help="Hugging Face dataset name")
    parser.add_argument("--batch_size", type=int, default=1000, help="Batch size for streaming")
    parser.add_argument("--max_samples", type=int, default=50000, help="Max samples to stream")
    args = parser.parse_args()

    train_streaming_model(
        dataset_name=args.dataset,
        batch_size=args.batch_size,
        max_samples=args.max_samples
    )
