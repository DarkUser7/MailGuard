"""Tests for SpamDetector machine learning model component."""

import os
import sys
from typing import Dict, Any

# Ensure project root directory is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from ml.src.predict import SpamDetector

# Path to trained model artifacts
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
MODEL_EXISTS = os.path.exists(os.path.join(MODEL_DIR, 'spam_model.pkl'))


@pytest.mark.skipif(not MODEL_EXISTS, reason="Model not trained yet")
class TestSpamDetector:
    """Test suite for the SpamDetector classification and probability estimation."""

    @pytest.fixture(autouse=True)
    def setup_detector(self) -> None:
        """Initialize the SpamDetector instance before each test."""
        self.detector = SpamDetector(model_dir=MODEL_DIR)

    def test_prediction_format(self) -> None:
        """Test that predict() returns expected dictionary structure with required keys."""
        sample_email: str = (
            "Hi team, just a reminder that the engineering sync is scheduled for "
            "tomorrow at 10:00 AM in Conference Room B."
        )
        result: Dict[str, Any] = self.detector.predict(sample_email)

        # Verify returned data type and structure
        assert isinstance(result, dict), "Result should be a dictionary"
        assert 'prediction' in result, "Missing 'prediction' key in result"
        assert 'spam_probability' in result, "Missing 'spam_probability' key in result"
        assert 'ham_probability' in result, "Missing 'ham_probability' key in result"
        assert 'confidence' in result, "Missing 'confidence' key in result"

        # Verify prediction is a valid label
        assert result['prediction'] in ['spam', 'ham'], (
            f"Expected 'spam' or 'ham', got {result['prediction']}"
        )

    def test_spam_detection(self) -> None:
        """Test that known spam/phishing text is accurately classified as 'spam'."""
        spam_email: str = (
            "URGENT: CONGRATULATIONS! You have won a $1,000,000 cash prize in our lottery! "
            "Click here immediately to claim your free reward and enter your bank account details."
        )
        result: Dict[str, Any] = self.detector.predict(spam_email)
        assert result['prediction'] == 'spam', (
            f"Expected 'spam' prediction for lottery email, got '{result['prediction']}'"
        )
        assert result['spam_probability'] > 0.5, "Spam probability should exceed 50%"

    def test_ham_detection(self) -> None:
        """Test that known legitimate text is accurately classified as 'ham'."""
        ham_email: str = (
            "Good morning Sarah, could you please review the attached design document "
            "before our afternoon sprint review? Let me know if you have any questions."
        )
        result: Dict[str, Any] = self.detector.predict(ham_email)
        assert result['prediction'] == 'ham', (
            f"Expected 'ham' prediction for legitimate message, got '{result['prediction']}'"
        )
        assert result['ham_probability'] > 0.5, "Ham probability should exceed 50%"

    def test_probability_range(self) -> None:
        """Test that all probability values fall strictly within the [0, 1] range."""
        sample_email: str = (
            "Important project update regarding the Q4 deployment schedule. "
            "Please check the repository for details."
        )
        result: Dict[str, Any] = self.detector.predict(sample_email)

        assert 0.0 <= result['spam_probability'] <= 1.0, (
            f"spam_probability out of bounds: {result['spam_probability']}"
        )
        assert 0.0 <= result['ham_probability'] <= 1.0, (
            f"ham_probability out of bounds: {result['ham_probability']}"
        )
        assert 0.0 <= result['confidence'] <= 1.0, (
            f"confidence out of bounds: {result['confidence']}"
        )

    def test_probabilities_sum(self) -> None:
        """Test that spam_probability and ham_probability sum approximately to 1.0."""
        sample_email: str = (
            "Notice of account verification required. Please review your recent profile activity."
        )
        result: Dict[str, Any] = self.detector.predict(sample_email)
        total_probability: float = result['spam_probability'] + result['ham_probability']

        # Check sum with tolerance due to float rounding
        assert pytest.approx(total_probability, abs=1e-3) == 1.0, (
            f"Probabilities do not sum to 1.0: {total_probability}"
        )
