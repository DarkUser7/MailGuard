"""Unit tests for URL extraction and VirusTotal URL analysis module."""

import os
import sys
from typing import Dict, Any, List

# Ensure project root is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from analyzer.url_analyzer import URLAnalyzer, extract_urls
from analyzer.virustotal import (
    get_url_id,
    query_virustotal_url,
    analyze_urls_with_virustotal
)
from ml.src.predict import SpamDetector


class TestURLExtraction:
    """Test suite for URL extraction, deduplication, and syntax handling."""

    def test_case_1_no_url(self) -> None:
        """Test 1 — No URL in text returns empty list and count 0."""
        text = "Hello, how are you? Let us catch up tomorrow."
        urls = extract_urls(text)
        assert len(urls) == 0, f"Expected 0 URLs, got {len(urls)}"
        
        analyzer = URLAnalyzer()
        res = analyzer.analyze(text)
        assert res['url_count'] == 0
        assert len(res['unique_urls']) == 0

    def test_case_2_one_url(self) -> None:
        """Test 2 — Exactly one URL is extracted correctly."""
        text = "Visit https://example.com to view your dashboard."
        urls = extract_urls(text)
        assert len(urls) == 1
        assert urls[0] == "https://example.com"

    def test_case_3_multiple_urls(self) -> None:
        """Test 3 — Multiple distinct URLs are extracted in order."""
        text = "Visit https://example.com and https://google.com for more info."
        urls = extract_urls(text)
        assert len(urls) == 2
        assert urls[0] == "https://example.com"
        assert urls[1] == "https://google.com"

    def test_case_4_duplicate_urls(self) -> None:
        """Test 4 — Duplicate URLs are deduplicated without losing unique links."""
        text = (
            "Hello,\n\n"
            "Please visit:\n"
            "https://example.com\n"
            "https://google.com\n\n"
            "Also check https://example.com again."
        )
        urls = extract_urls(text)
        assert len(urls) == 2, f"Expected 2 unique URLs, got {len(urls)}"
        assert urls == ["https://example.com", "https://google.com"]

    def test_html_href_extraction(self) -> None:
        """Test extracting URLs from HTML <a> href attributes."""
        html_text = '<p>Click <a href="https://secure-login.portal.com/auth">here</a> to login or visit https://fallback.org.</p>'
        urls = extract_urls(html_text)
        assert "https://secure-login.portal.com/auth" in urls
        assert "https://fallback.org" in urls
        assert len(urls) == 2

    def test_url_id_generation(self) -> None:
        """Test VirusTotal v3 URL ID generation (base64url without padding)."""
        url = "https://example.com"
        url_id = get_url_id(url)
        assert isinstance(url_id, str)
        assert not url_id.endswith("=")
        assert len(url_id) > 0


class TestVirusTotalIntegration:
    """Test suite for VirusTotal query handling and resilience."""

    def test_case_5_virustotal_unavailable_no_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test 5 — When VirusTotal API key is missing or unset, returns structured unavailable status without crashing."""
        monkeypatch.delenv("VT_API_KEY", raising=False)
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

        res = query_virustotal_url("https://test-link.com", api_key=None)
        assert res['status'] == "unavailable"
        assert res['classification'] == "⚠️ Analysis Unavailable"
        assert res['malicious'] == 0
        assert "API key" in res['error_message']

    def test_virustotal_aggregate_empty(self) -> None:
        """Test aggregate VirusTotal analysis with empty URL list."""
        summary = analyze_urls_with_virustotal([])
        assert summary['urls_detected'] == 0
        assert summary['urls_analyzed'] == 0
        assert len(summary['results']) == 0

    def test_ml_remains_functional_when_vt_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify that ML model prediction continues working completely independently even when VT is unavailable."""
        monkeypatch.delenv("VT_API_KEY", raising=False)
        
        # Test ML model prediction
        detector = SpamDetector()
        ml_res = detector.predict("URGENT: Your account has been suspended! Click http://phish.com immediately.")
        assert ml_res['prediction'] in ['spam', 'ham']
        assert 0.0 <= ml_res['spam_probability'] <= 1.0

        # Test VT analysis
        vt_res = analyze_urls_with_virustotal(["http://phish.com"])
        assert vt_res['urls_detected'] == 1
        assert vt_res['unavailable_count'] == 1
