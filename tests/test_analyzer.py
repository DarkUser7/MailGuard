"""Unit tests for rule-based security analyzers and the risk scoring engine.

These tests validate URL detection, keyword heuristics, pattern/anomaly detection,
and weighted risk aggregation without requiring trained machine learning models.
"""

import os
import sys
from typing import Dict, Any

# Ensure project root directory is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from analyzer.url_analyzer import URLAnalyzer
from analyzer.keyword_analyzer import KeywordAnalyzer
from analyzer.pattern_analyzer import PatternAnalyzer
from analyzer.header_analyzer import HeaderAnalyzer
from analyzer.risk_engine import RiskEngine


# ============================================================================
# URLAnalyzer Tests
# ============================================================================

class TestURLAnalyzer:
    """Test suite for URL extraction and suspicious pattern detection."""

    @pytest.fixture(autouse=True)
    def setup_analyzer(self) -> None:
        """Initialize the URLAnalyzer instance before each test."""
        self.analyzer = URLAnalyzer()

    def test_no_urls(self) -> None:
        """Test that plain text containing no URLs returns url_count=0."""
        text: str = "Good morning team, let us meet in the second floor meeting room."
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['url_count'] == 0, f"Expected 0 URLs, got {result['url_count']}"
        assert result['suspicious_url_count'] == 0, "Expected 0 suspicious URLs"
        assert len(result['urls']) == 0, "URL list should be empty"
        assert len(result['suspicious_urls']) == 0, "Suspicious URL list should be empty"

    def test_detect_urls(self) -> None:
        """Test that text containing multiple URLs returns the accurate URL count."""
        text: str = (
            "Documentation is available at https://docs.python.org and "
            "source code is hosted at http://github.com/project."
        )
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['url_count'] == 2, f"Expected 2 URLs, got {result['url_count']}"
        assert len(result['urls']) == 2, "List of detected URLs should have length 2"

    def test_suspicious_url(self) -> None:
        """Test that an IP-based URL is flagged as suspicious with appropriate reason."""
        text: str = "Please authenticate your credentials immediately at http://192.168.1.50/login"
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['url_count'] == 1, "Expected 1 URL detected"
        assert result['suspicious_url_count'] >= 1, "IP-based URL should be flagged as suspicious"

        # Check that reasons mention IP address
        flagged_reasons: list = [
            reason
            for item in result['suspicious_urls']
            for reason in item.get('reasons', [])
        ]
        assert any("IP address" in reason for reason in flagged_reasons), (
            f"Expected IP address warning, found: {flagged_reasons}"
        )

    def test_url_shortener(self) -> None:
        """Test that known URL shorteners (e.g., bit.ly) are flagged as suspicious."""
        text: str = "Claim your special promotional prize right here: https://bit.ly/promo2026"
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['url_count'] == 1, "Expected 1 URL detected"
        assert result['suspicious_url_count'] >= 1, "URL shortener should be flagged as suspicious"

        # Check reasons for URL shortener notice
        flagged_reasons: list = [
            reason
            for item in result['suspicious_urls']
            for reason in item.get('reasons', [])
        ]
        assert any("shortener" in reason.lower() for reason in flagged_reasons), (
            f"Expected shortener warning, found: {flagged_reasons}"
        )


# ============================================================================
# KeywordAnalyzer Tests
# ============================================================================

class TestKeywordAnalyzer:
    """Test suite for detecting urgency, financial, threat, and action keywords."""

    @pytest.fixture(autouse=True)
    def setup_analyzer(self) -> None:
        """Initialize the KeywordAnalyzer instance before each test."""
        self.analyzer = KeywordAnalyzer()

    def test_no_keywords(self) -> None:
        """Test that benign business text with no spam triggers returns zero counts."""
        text: str = (
            "Hi team, the quarterly planning session is scheduled for Thursday afternoon. "
            "Please review the attached project agenda beforehand."
        )
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['urgency_count'] == 0
        assert result['financial_count'] == 0
        assert result['threat_count'] == 0
        assert result['action_count'] == 0
        assert result['total_suspicious_keywords'] == 0

    def test_urgency_detection(self) -> None:
        """Test that urgency trigger words such as 'urgent' and 'act now' are detected."""
        text: str = "This matter is urgent! You must act now before the offer deadline expires."
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['urgency_count'] >= 2, (
            f"Expected at least 2 urgency keywords, got {result['urgency_count']}"
        )
        detected_urgency: list = result['found_keywords'].get('urgency', [])
        assert 'urgent' in detected_urgency
        assert 'act now' in detected_urgency

    def test_financial_detection(self) -> None:
        """Test that financial lures such as 'free' and 'winner' are detected."""
        text: str = "You are our lucky winner! You have received a free gift card bonus today."
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['financial_count'] >= 2, (
            f"Expected at least 2 financial keywords, got {result['financial_count']}"
        )
        detected_financial: list = result['found_keywords'].get('financial', [])
        assert 'free' in detected_financial
        assert 'winner' in detected_financial

    def test_case_insensitive(self) -> None:
        """Test that keyword detection is case-insensitive (e.g. URGENT vs urgent)."""
        lower_text: str = "urgent: please respond right away."
        upper_text: str = "URGENT: PLEASE RESPOND RIGHT AWAY."

        lower_res: Dict[str, Any] = self.analyzer.analyze(lower_text)
        upper_res: Dict[str, Any] = self.analyzer.analyze(upper_text)

        assert lower_res['urgency_count'] == upper_res['urgency_count'], (
            f"Counts differ: lower={lower_res['urgency_count']} vs upper={upper_res['urgency_count']}"
        )
        assert 'urgent' in upper_res['found_keywords']['urgency']


# ============================================================================
# PatternAnalyzer Tests
# ============================================================================

class TestPatternAnalyzer:
    """Test suite for structural, capitalization, and punctuation anomaly detection."""

    @pytest.fixture(autouse=True)
    def setup_analyzer(self) -> None:
        """Initialize the PatternAnalyzer instance before each test."""
        self.analyzer = PatternAnalyzer()

    def test_normal_text(self) -> None:
        """Test that normally formatted text raises no pattern flags."""
        text: str = (
            "Hi David, thanks for sending over the revision. The layout looks "
            "clean and ready for deployment tomorrow morning."
        )
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['excessive_caps'] is False
        assert result['excessive_punctuation'] is False
        assert len(result['patterns_found']) == 0

    def test_excessive_caps(self) -> None:
        """Test that text with high uppercase ratio (>30%) and length >20 is flagged."""
        text: str = "ATTENTION ALL USERS: IMMEDIATE ACTION REQUIRED TO PREVENT ACCOUNT DELETION!"
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['excessive_caps'] is True
        assert result['caps_percentage'] > 30.0
        assert "Excessive capitalization" in result['patterns_found']

    def test_excessive_punctuation(self) -> None:
        """Test that text containing repeated punctuation marks like '!!!' is flagged."""
        text: str = "Claim your exclusive grand lottery prize right now!!!"
        result: Dict[str, Any] = self.analyzer.analyze(text)

        assert result['excessive_punctuation'] is True
        assert "Excessive or repeated punctuation" in result['patterns_found']


# ============================================================================
# RiskEngine Tests
# ============================================================================

class TestRiskEngine:
    """Test suite for overall risk score aggregation and level classification."""

    @pytest.fixture(autouse=True)
    def setup_engine(self) -> None:
        """Initialize the RiskEngine instance before each test."""
        self.engine = RiskEngine()

    def test_low_risk(self) -> None:
        """Test that clean emails with no threat indicators score LOW."""
        ml_result: Dict[str, Any] = {
            'prediction': 'ham',
            'spam_probability': 0.05,
            'ham_probability': 0.95,
            'confidence': 0.95
        }
        url_analysis: Dict[str, Any] = {
            'url_count': 0,
            'suspicious_url_count': 0,
            'urls': [],
            'suspicious_urls': []
        }
        keyword_analysis: Dict[str, Any] = {
            'urgency_count': 0,
            'financial_count': 0,
            'threat_count': 0,
            'action_count': 0,
            'total_suspicious_keywords': 0,
            'found_keywords': {}
        }
        pattern_analysis: Dict[str, Any] = {
            'excessive_caps': False,
            'excessive_punctuation': False,
            'patterns_found': []
        }

        result: Dict[str, Any] = self.engine.calculate_risk(
            ml_result, url_analysis, keyword_analysis, pattern_analysis
        )

        assert result['risk_level'] == 'LOW'
        assert result['risk_score'] <= 20
        assert len(result['contributing_factors']) == 0

    def test_high_risk(self) -> None:
        """Test that emails with multiple spam and security indicators score HIGH or CRITICAL."""
        ml_result: Dict[str, Any] = {
            'prediction': 'spam',
            'spam_probability': 0.96,
            'ham_probability': 0.04,
            'confidence': 0.96
        }
        url_analysis: Dict[str, Any] = {
            'url_count': 2,
            'suspicious_url_count': 1,
            'urls': ['http://192.168.1.1/login', 'https://example.com'],
            'suspicious_urls': [{'url': 'http://192.168.1.1/login', 'reasons': ['IP address']}]
        }
        keyword_analysis: Dict[str, Any] = {
            'urgency_count': 2,
            'financial_count': 1,
            'threat_count': 1,
            'action_count': 1,
            'total_suspicious_keywords': 5,
            'found_keywords': {
                'urgency': ['urgent', 'act now'],
                'financial': ['free'],
                'threat': ['suspended'],
                'action': ['click here']
            }
        }
        pattern_analysis: Dict[str, Any] = {
            'excessive_caps': True,
            'excessive_punctuation': True,
            'patterns_found': ['Excessive capitalization', 'Excessive or repeated punctuation']
        }

        result: Dict[str, Any] = self.engine.calculate_risk(
            ml_result, url_analysis, keyword_analysis, pattern_analysis
        )

        assert result['risk_level'] in ['HIGH', 'CRITICAL']
        assert result['risk_score'] >= 75
        assert len(result['contributing_factors']) > 0

    def test_score_range(self) -> None:
        """Test that risk score is strictly bounded between 0 and 100 in all scenarios."""
        # Scenario 1: Minimum baseline
        clean_ml: Dict[str, Any] = {'spam_probability': 0.0}
        clean_url: Dict[str, Any] = {'suspicious_url_count': 0}
        clean_kw: Dict[str, Any] = {'urgency_count': 0, 'financial_count': 0, 'threat_count': 0, 'action_count': 0}
        clean_pat: Dict[str, Any] = {'excessive_caps': False, 'excessive_punctuation': False}

        clean_res: Dict[str, Any] = self.engine.calculate_risk(clean_ml, clean_url, clean_kw, clean_pat)
        assert 0 <= clean_res['risk_score'] <= 100
        assert clean_res['risk_score'] == 0

        # Scenario 2: Maximum possible points (>100 before capping)
        extreme_ml: Dict[str, Any] = {'spam_probability': 0.99}
        extreme_url: Dict[str, Any] = {'suspicious_url_count': 5}
        extreme_kw: Dict[str, Any] = {'urgency_count': 3, 'financial_count': 2, 'threat_count': 2, 'action_count': 2}
        extreme_pat: Dict[str, Any] = {'excessive_caps': True, 'excessive_punctuation': True}

        extreme_res: Dict[str, Any] = self.engine.calculate_risk(extreme_ml, extreme_url, extreme_kw, extreme_pat)
        assert 0 <= extreme_res['risk_score'] <= 100
        assert extreme_res['risk_score'] == 100


# ============================================================================
# HeaderAnalyzer Tests
# ============================================================================

class TestHeaderAnalyzer:
    """Test suite for parsing RFC headers, SPF/DKIM/DMARC verdicts, and spoofing detection."""

    @pytest.fixture(autouse=True)
    def setup_analyzer(self) -> None:
        """Initialize the HeaderAnalyzer instance before each test."""
        self.analyzer = HeaderAnalyzer()

    def test_empty_headers(self) -> None:
        """Test that empty header string returns has_headers=False without errors."""
        res: Dict[str, Any] = self.analyzer.analyze("")
        assert res['has_headers'] is False
        assert res['risk_points'] == 0

    def test_spoofing_detection(self) -> None:
        """Test that mismatched From and Return-Path domains trigger spoofing alert."""
        raw_header = (
            "From: PayPal Support <support@paypal.com>\n"
            "Return-Path: <attacker@scam-server.xyz>\n"
            "Subject: Account Locked\n"
        )
        res: Dict[str, Any] = self.analyzer.analyze(raw_header)
        assert res['has_headers'] is True
        assert res['spoofing_detected'] is True
        assert any("Domain Mismatch" in a for a in res['anomalies'])

    def test_spf_fail(self) -> None:
        """Test that SPF failure is accurately parsed."""
        raw_header = (
            "From: test@example.com\n"
            "Received-SPF: fail (domain of example.com does not designate sender IP)\n"
            "Subject: Test Email\n"
        )
        res: Dict[str, Any] = self.analyzer.analyze(raw_header)
        assert res['auth_results']['spf'] == 'FAIL'
        assert any("SPF Authentication FAIL" in a for a in res['anomalies'])

    def test_legitimate_headers(self) -> None:
        """Test that legitimate aligned headers with passing auth pass without spoofing alerts."""
        raw_header = (
            "From: alice@trusted.com\n"
            "Return-Path: <alice@trusted.com>\n"
            "Subject: Team Sync\n"
            "Message-ID: <msg12345@trusted.com>\n"
            "Received-SPF: pass\n"
            "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n"
        )
        res: Dict[str, Any] = self.analyzer.analyze(raw_header)
        assert res['has_headers'] is True
        assert res['spoofing_detected'] is False
        assert res['auth_results']['spf'] == 'PASS'
        assert res['auth_results']['dkim'] == 'PASS'
        assert res['auth_results']['dmarc'] == 'PASS'

