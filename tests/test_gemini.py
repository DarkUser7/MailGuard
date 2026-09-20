"""Unit tests for Gemini AI integration components and template report generator.

These tests verify prompt construction, fallback report generation, section integrity,
and client availability handling without making external network calls to Gemini APIs.
"""

import os
import sys
from typing import Dict, Any

# Ensure project root directory is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from gemini.client import GeminiClient
from gemini.prompts import build_report_prompt
from gemini.report_generator import ReportGenerator


@pytest.fixture
def mock_scan_data() -> Dict[str, Any]:
    """Provide structured mock scan data representing an analyzed email."""
    return {
        'ml_result': {
            'prediction': 'spam',
            'spam_probability': 0.9425,
            'ham_probability': 0.0575,
            'confidence': 0.9425
        },
        'url_analysis': {
            'url_count': 2,
            'suspicious_url_count': 1,
            'urls': ['https://bit.ly/secure-account', 'https://example.com'],
            'suspicious_urls': [{
                'url': 'https://bit.ly/secure-account',
                'reasons': ['URL shortener used', 'Suspicious keywords in URL']
            }]
        },
        'keyword_analysis': {
            'urgency_count': 1,
            'financial_count': 1,
            'threat_count': 1,
            'action_count': 1,
            'total_suspicious_keywords': 4,
            'found_keywords': {
                'urgency': ['urgent'],
                'financial': ['won'],
                'threat': ['suspended'],
                'action': ['log in']
            }
        },
        'pattern_analysis': {
            'caps_percentage': 42.5,
            'excessive_caps': True,
            'exclamation_count': 6,
            'excessive_punctuation': True,
            'repeated_punctuation_count': 1,
            'has_html': False,
            'money_references': ['$1,000'],
            'phone_numbers': [],
            'email_addresses': ['support@bank-security.xyz'],
            'patterns_found': [
                'Excessive capitalization',
                'Excessive or repeated punctuation',
                'Contains money references'
            ]
        },
        'risk_result': {
            'risk_score': 90,
            'risk_level': 'CRITICAL',
            'contributing_factors': [
                {'factor': 'Suspicious URLs', 'points': 30, 'description': 'Found 1 suspicious URL(s).'},
                {'factor': 'Urgency Keywords', 'points': 20, 'description': 'Urgency language detected.'},
                {'factor': 'Financial Keywords', 'points': 20, 'description': 'Financial lures detected.'},
                {'factor': 'ML Model Confidence', 'points': 15, 'description': 'High spam probability.'}
            ]
        }
    }


class TestGeminiComponents:
    """Test suite for Gemini AI prompt builder and report generation."""

    def test_prompt_generation(self, mock_scan_data: Dict[str, Any]) -> None:
        """Test that build_report_prompt generates a non-empty prompt containing key scan metrics."""
        prompt: str = build_report_prompt(
            ml_result=mock_scan_data['ml_result'],
            url_analysis=mock_scan_data['url_analysis'],
            keyword_analysis=mock_scan_data['keyword_analysis'],
            pattern_analysis=mock_scan_data['pattern_analysis'],
            risk_result=mock_scan_data['risk_result']
        )

        assert isinstance(prompt, str), "Prompt must be a string"
        assert len(prompt.strip()) > 0, "Prompt must not be empty"

        # Verify key data points are embedded in the prompt
        assert "SPAM" in prompt, "Prompt should contain classification outcome"
        assert "94.25%" in prompt or "0.94" in prompt, "Prompt should contain spam probability"
        assert "bit.ly" in prompt, "Prompt should contain suspicious URL details"
        assert "CRITICAL" in prompt, "Prompt should contain risk level"
        assert "90/100" in prompt, "Prompt should contain risk score"
        assert "RECOMMENDED ACTIONS" in prompt, "Prompt should include expected report structure"

    def test_fallback_report(self, mock_scan_data: Dict[str, Any]) -> None:
        """Test that ReportGenerator._generate_fallback_report returns properly formatted report text."""
        generator: ReportGenerator = ReportGenerator()
        fallback_text: str = generator._generate_fallback_report(
            ml_result=mock_scan_data['ml_result'],
            url_analysis=mock_scan_data['url_analysis'],
            keyword_analysis=mock_scan_data['keyword_analysis'],
            pattern_analysis=mock_scan_data['pattern_analysis'],
            risk_result=mock_scan_data['risk_result']
        )

        assert isinstance(fallback_text, str), "Fallback report must be a string"
        assert len(fallback_text.strip()) > 0, "Fallback report must not be empty"
        assert "EMAIL SECURITY REPORT" in fallback_text
        assert "SPAM" in fallback_text
        assert "90/100" in fallback_text

    def test_report_contains_sections(self, mock_scan_data: Dict[str, Any]) -> None:
        """Test that the fallback report includes all 5 required structural sections."""
        generator: ReportGenerator = ReportGenerator()
        fallback_text: str = generator._generate_fallback_report(
            ml_result=mock_scan_data['ml_result'],
            url_analysis=mock_scan_data['url_analysis'],
            keyword_analysis=mock_scan_data['keyword_analysis'],
            pattern_analysis=mock_scan_data['pattern_analysis'],
            risk_result=mock_scan_data['risk_result']
        )

        expected_sections = [
            "1. CLASSIFICATION SUMMARY",
            "2. DETECTED ISSUES",
            "3. ANALYSIS",
            "4. RISK INTERPRETATION",
            "5. RECOMMENDED ACTIONS"
        ]

        for section in expected_sections:
            assert section in fallback_text, (
                f"Missing expected section '{section}' in fallback report"
            )

    def test_gemini_client_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that GeminiClient reports is_available() == False when no valid API key is present."""
        # Case 1: Empty API key
        monkeypatch.setenv('GEMINI_API_KEY', '')
        client_empty = GeminiClient()
        assert client_empty.is_available() is False, (
            "GeminiClient should be unavailable when GEMINI_API_KEY is empty"
        )

        # Case 2: Placeholder API key from .env.example
        monkeypatch.setenv('GEMINI_API_KEY', 'your_api_key_here')
        client_placeholder = GeminiClient()
        assert client_placeholder.is_available() is False, (
            "GeminiClient should be unavailable when GEMINI_API_KEY is placeholder"
        )

        # Case 3: Missing GEMINI_API_KEY environment variable
        monkeypatch.delenv('GEMINI_API_KEY', raising=False)
        client_missing = GeminiClient()
        assert client_missing.is_available() is False, (
            "GeminiClient should be unavailable when GEMINI_API_KEY is unset"
        )
