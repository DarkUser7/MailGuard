"""Streaming data loader for Hugging Face datasets.

Streams email and SMS spam datasets without downloading full datasets locally.
"""

from typing import Generator, Tuple, List, Optional
import numpy as np


def get_dataset_stream(
    dataset_name: str = "SetFit/enron_spam",
    split: str = "train"
):
    """Load a streaming dataset from Hugging Face.
    
    Popular streaming datasets:
    - 'SetFit/enron_spam' (text, label: 0=ham, 1=spam)
    - 'sms_spam' (sms, label: 0=ham, 1=spam)
    - 'talby/spamassassin'
    """
    try:
        from datasets import load_dataset
    except ImportError:
        raise ImportError(
            "The 'datasets' package is required for streaming. "
            "Install it via: pip install datasets"
        )
        
    return load_dataset(dataset_name, split=split, streaming=True)


def parse_sample(sample: dict) -> Tuple[Optional[str], Optional[int]]:
    """Extract and normalize text and label from various HF dataset formats.

    Special handling for locuoco/the-biggest-spam-ham-phish-email-dataset-300000:
        label 0 = ham, 1 = phish, 2 = spam  -> mapped to 0=ham, 1=spam
    Generic fallback: supports SetFit/enron_spam, sms_spam, spamassassin, etc.
    """
    # Extract text
    text = (
        sample.get("text")
        or sample.get("sms")
        or sample.get("message")
        or sample.get("email")
        or sample.get("body")
    )
    if not isinstance(text, str) or not text.strip():
        return None, None

    # Extract & normalize label to 0 (ham) or 1 (spam)
    raw_label = sample.get("label") if "label" in sample else sample.get("label_text")
    if raw_label is None:
        raw_label = sample.get("Category") or sample.get("target")

    if isinstance(raw_label, (int, np.integer)):
        raw_int = int(raw_label)
        # locuoco mapping: 1 (phish) and 2 (spam) -> spam (1)
        if raw_int in (1, 2):
            label = 1
        elif raw_int == 0:
            label = 0
        else:
            label = 1 if raw_int != 0 else 0
    elif isinstance(raw_label, str):
        low = raw_label.lower().strip()
        if low in ["spam", "phish", "phishing", "1", "true"]:
            label = 1
        elif low in ["ham", "0", "false"]:
            label = 0
        else:
            label = 1 if low in ["spam", "1", "true"] else 0
    else:
        label = 0

    return text, label


def stream_batches(
    dataset_name: str = "SetFit/enron_spam",
    split: str = "train",
    batch_size: int = 500,
    max_samples: Optional[int] = None
) -> Generator[Tuple[List[str], List[int]], None, None]:
    """Yield batches of (texts, labels) directly from the stream.
    
    Args:
        dataset_name: Hugging Face dataset identifier.
        split: Dataset split ('train', 'test', etc.).
        batch_size: Number of samples per batch.
        max_samples: Optional limit on total samples streamed.
    """
    dataset = get_dataset_stream(dataset_name=dataset_name, split=split)
    
    batch_texts = []
    batch_labels = []
    total_processed = 0
    
    for sample in dataset:
        text, label = parse_sample(sample)
        if text is None or label is None:
            continue
            
        batch_texts.append(text)
        batch_labels.append(label)
        total_processed += 1
        
        if len(batch_texts) >= batch_size:
            yield batch_texts, batch_labels
            batch_texts = []
            batch_labels = []
            
        if max_samples and total_processed >= max_samples:
            break
            
    if batch_texts:
        yield batch_texts, batch_labels
