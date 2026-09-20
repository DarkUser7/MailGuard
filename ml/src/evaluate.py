import os
import sys
import json
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

try:
    from ml.src.preprocessing import load_and_clean_dataset
except ImportError:
    from preprocessing import load_and_clean_dataset

def evaluate_model(data_path: str = None, model_dir: str = 'models'):
    # Auto-resolve to 50K if present
    if data_path is None:
        for cand in ['data/processed/email_dataset_50k.csv', 'data/raw/email_dataset.csv', 'data/processed/cleaned_dataset.csv']:
            if os.path.exists(cand):
                data_path = cand
                break
        if data_path is None:
            data_path = 'data/raw/email_dataset.csv'
    print(f"[evaluate] Using dataset: {data_path}")
    df = load_and_clean_dataset(data_path)
    X = df['cleaned_text']
    # Support both string and int labels
    if df['label'].dtype == object:
        y = (df['label'].astype(str).str.lower() == 'spam').astype(int)
    else:
        y = (df['label'] == 1).astype(int)
    
    model = joblib.load(os.path.join(model_dir, 'spam_model.pkl'))
    vectorizer = joblib.load(os.path.join(model_dir, 'tfidf_vectorizer.pkl'))
    
    X_tfidf = vectorizer.transform(X)
    y_pred = model.predict(X_tfidf)
    y_prob = model.predict_proba(X_tfidf)[:, 1]
    
    report = classification_report(y, y_pred, target_names=['ham', 'spam'], output_dict=True)
    cm = confusion_matrix(y, y_pred)
    roc_auc = roc_auc_score(y, y_prob)
    
    metrics = {
        'roc_auc': float(roc_auc),
        'classification_report': report,
        'confusion_matrix': cm.tolist()
    }
    
    os.makedirs(model_dir, exist_ok=True)
    with open(os.path.join(model_dir, 'evaluation_metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=2)
        
    print("Evaluation Complete. Metrics saved.")

if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    evaluate_model()
