"""URL Extractor and Heuristic Analyzer for MailGuard AI.

Extracts all HTTP/HTTPS URLs from plain text and HTML emails, removes duplicates,
handles malformed links, and checks for suspicious heuristic patterns.
"""

import re
from typing import Dict, Any, List, Set
from urllib.parse import urlparse


def extract_urls(text: str) -> List[str]:
    """Extract all unique HTTP/HTTPS URLs from text or HTML while preserving order.
    
    Args:
        text (str): Input email text or HTML body.
        
    Returns:
        List[str]: List of unique, clean URLs.
    """
    if not text or not isinstance(text, str):
        return []

    found_urls: List[str] = []
    seen: Set[str] = set()

    # 1. Extract URLs from HTML href attributes if present
    html_href_pattern = re.compile(r'href=[\'"](https?://[^\'">\s]+|www\.[^\'">\s]+)[\'"]', re.IGNORECASE)
    for match in html_href_pattern.findall(text):
        clean_url = _clean_url(match)
        if clean_url and clean_url not in seen:
            seen.add(clean_url)
            found_urls.append(clean_url)

    # 2. Extract standard URLs from plain text
    url_pattern = re.compile(r'\b(https?://[^\s<>"\')\]}]+|www\.[^\s<>"\')\]}]+)', re.IGNORECASE)
    for match in url_pattern.findall(text):
        clean_url = _clean_url(match)
        if clean_url and clean_url not in seen:
            seen.add(clean_url)
            found_urls.append(clean_url)

    return found_urls


def _clean_url(url: str) -> str:
    """Normalize and clean trailing punctuation from extracted URL."""
    if not url:
        return ""
    # Strip trailing punctuation marks commonly attached in sentences
    cleaned = re.sub(r'[.,;!?"\'\)\]\}>]+$', '', url.strip())
    # Ensure scheme
    if cleaned.lower().startswith('www.'):
        cleaned = 'http://' + cleaned
    return cleaned


class URLAnalyzer:
    """Analyzes URLs found in email text for heuristic threats and suspicious patterns."""

    IP_REGEX = re.compile(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'cutt.ly', 'tiny.cc'
    }
    SUSPICIOUS_TLDS = {'.xyz', '.top', '.click', '.loan', '.work', '.tk', '.ml', '.ga', '.cf', '.gq', '.rest'}
    SUSPICIOUS_KEYWORDS = {'login', 'account', 'verify', 'secure', 'update', 'signin', 'auth', 'banking', 'wallet', 'confirm'}

    def extract_urls(self, text: str) -> List[str]:
        """Helper method to extract unique URLs."""
        return extract_urls(text)

    def analyze(self, text: str) -> Dict[str, Any]:
        """Extract and analyze all URLs in the provided text.
        
        Args:
            text (str): The text content to analyze.
            
        Returns:
            Dict[str, Any]: Structured heuristic analysis of URLs.
        """
        urls = extract_urls(text)
        suspicious_urls = []

        for url in urls:
            reasons = []
            try:
                parsed = urlparse(url)
                netloc = parsed.netloc.lower()
                path = parsed.path.lower()

                # Check IP-based host
                if self.IP_REGEX.match(url):
                    reasons.append("IP address used instead of domain name")

                # Check shorteners
                if any(netloc == short or netloc.endswith('.' + short) for short in self.SHORTENERS):
                    reasons.append("URL shortener used")

                # Check excessive subdomains (> 3 dots in hostname)
                if netloc.count('.') > 3:
                    reasons.append("Excessive subdomains")

                # Check suspicious TLDs
                if any(netloc.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                    reasons.append("Suspicious Top-Level Domain (TLD)")

                # Check URL length
                if len(url) > 100:
                    reasons.append("Unusually long URL")

                # Check sensitive credential/action keywords in URL
                if any(kw in url.lower() for kw in self.SUSPICIOUS_KEYWORDS):
                    reasons.append("Suspicious keywords in URL (e.g. login, verify, banking)")

            except Exception as e:
                reasons.append(f"Malformed URL syntax: {e}")

            if reasons:
                suspicious_urls.append({
                    'url': url,
                    'reasons': reasons
                })

        return {
            'url_count': len(urls),
            'unique_urls': urls,
            'suspicious_url_count': len(suspicious_urls),
            'urls': urls,
            'suspicious_urls': suspicious_urls
        }
