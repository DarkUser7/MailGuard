import re
import pandas as pd
import nltk
from nltk.corpus import stopwords

_STOPWORDS_CACHE = None

def download_nltk_data():
    """Download required NLTK data."""
    for resource in ['stopwords', 'punkt', 'punkt_tab']:
        try:
            nltk.data.find(f'tokenizers/{resource}' if 'punkt' in resource else f'corpora/{resource}')
        except LookupError:
            nltk.download(resource, quiet=True)

def _get_stopwords():
    global _STOPWORDS_CACHE
    if _STOPWORDS_CACHE is None:
        download_nltk_data()
        _STOPWORDS_CACHE = set(stopwords.words('english'))
    return _STOPWORDS_CACHE

def clean_text(text: str) -> str:
    """Clean and normalize email text."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r'<[^>]+>', ' ', text)  # Remove HTML tags
    text = re.sub(r'http[s]?://\S+', ' ', text)  # Remove URLs
    text = re.sub(r'\S+@\S+', ' ', text)  # Remove emails
    text = re.sub(r'[^a-zA-Z\s]', ' ', text)  # Remove special chars
    text = re.sub(r'\s+', ' ', text).strip()  # Normalize whitespace

    stop_words = _get_stopwords()
    tokens = text.split()
    tokens = [t for t in tokens if t not in stop_words and len(t) > 2]
    return ' '.join(tokens)

def load_and_clean_dataset(raw_path: str = 'data/raw/email_dataset.csv',
                           processed_path: str = 'data/processed/cleaned_dataset.csv') -> pd.DataFrame:
    """Load raw dataset, clean text, save processed version.

    Optimization: if `cleaned_text` already exists and is valid, skip re-cleaning
    (useful when training directly on data/processed/cleaned_dataset.csv).
    """
    import os
    df = pd.read_csv(raw_path)
    df = df.dropna(subset=['text'])
    df = df.drop_duplicates(subset=['text'])

    # If cleaned_text already present and non-empty, reuse it (fast path)
    if 'cleaned_text' in df.columns and df['cleaned_text'].notna().sum() > len(df) * 0.9:
        # Re-validate: remove rows where cleaned_text becomes empty after strip
        df['cleaned_text'] = df['cleaned_text'].astype(str)
        df = df[df['cleaned_text'].str.strip().astype(bool)]
        print(f"Dataset loaded (pre-cleaned): {len(df)} emails")
    else:
        df['cleaned_text'] = df['text'].apply(clean_text)
        df = df[df['cleaned_text'].str.len() > 0]
        print(f"Dataset cleaned: {len(df)} emails")

    # Only write back if source is not already the processed_path (avoid self-overwrite loop)
    # Still ensure processed_path gets updated if raw_path != processed_path
    try:
        vc = df['label'].astype(str).str.lower().str.strip().value_counts()
        spam_c = int(vc.get('spam', 0) + vc.get('1', 0))
        ham_c = int(vc.get('ham', 0) + vc.get('0', 0))
        # fallback numeric
        if spam_c == 0 and ham_c == 0:
            spam_c = int((df['label'] == 1).sum())
            ham_c = int((df['label'] == 0).sum())
        print(f"Spam: {spam_c}, Ham: {ham_c}")
    except Exception as e:
        print(f"(label count skipped: {e})")

    # Save only if processing a raw file (don't overwrite cleaned_dataset with itself unnecessarily)
    if os.path.abspath(raw_path) != os.path.abspath(processed_path):
        os.makedirs(os.path.dirname(processed_path), exist_ok=True)
        # Don't overwrite cleaned_dataset.csv if we just read it - skip write
        if 'cleaned_text' not in pd.read_csv(raw_path, nrows=1).columns:
            df.to_csv(processed_path, index=False)
    return df

if __name__ == '__main__':
    load_and_clean_dataset()
