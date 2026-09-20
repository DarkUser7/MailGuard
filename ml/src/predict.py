import os
import joblib
import re

class SpamDetector:
    """Spam detection using trained TF-IDF + Logistic Regression model."""
    
    def __init__(self, model_dir: str = 'models'):
        self.model_dir = model_dir
        self.model = None
        self.vectorizer = None
        self._load_model()
    
    def _load_model(self):
        model_path = os.path.join(self.model_dir, 'spam_model.pkl')
        vectorizer_path = os.path.join(self.model_dir, 'tfidf_vectorizer.pkl')
        
        if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
            raise FileNotFoundError(
                f"Model files not found in {self.model_dir}/. "
                "Run 'python ml/src/train.py' first."
            )
        
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
    
    def _preprocess(self, text: str) -> str:
        """Basic preprocessing for prediction (lighter than training)."""
        text = text.lower()
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'http[s]?://\S+', ' ', text)
        text = re.sub(r'\S+@\S+', ' ', text)
        text = re.sub(r'[^a-zA-Z\s]', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    def predict(self, text: str) -> dict:
        """Predict spam/ham for given email text."""
        cleaned = self._preprocess(text)
        tfidf_vector = self.vectorizer.transform([cleaned])
        
        prediction = self.model.predict(tfidf_vector)[0]
        probabilities = self.model.predict_proba(tfidf_vector)[0]
        
        label = 'spam' if prediction == 1 else 'ham'
        
        return {
            'prediction': label,
            'spam_probability': round(float(probabilities[1]), 4),
            'ham_probability': round(float(probabilities[0]), 4),
            'confidence': round(float(max(probabilities)), 4)
        }
