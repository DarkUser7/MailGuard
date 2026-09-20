"""VirusTotal API v3 URL Reputation and Security Intelligence Module.

Performs URL threat lookups using VirusTotal API v3 without modifying the ML model.
Safely extracts analysis statistics (malicious, suspicious, harmless, undetected)
and handles missing API keys, rate limits, and network errors gracefully.
"""

import os
import base64
import requests
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# In-memory session cache for non-Streamlit contexts or quick repeats
_MEMORY_CACHE: Dict[str, Dict[str, Any]] = {}


def get_vt_api_key() -> Optional[str]:
    """Retrieve VirusTotal API key from environment variables or Streamlit secrets."""
    # Check Streamlit secrets if available
    try:
        import streamlit as st
        if hasattr(st, "secrets") and "VT_API_KEY" in st.secrets:
            key = st.secrets["VT_API_KEY"]
            if key and str(key).strip() and str(key).strip() != "your_virustotal_api_key_here":
                return str(key).strip()
    except Exception:
        pass

    # Check environment variables
    for env_var in ["VT_API_KEY", "VIRUSTOTAL_API_KEY"]:
        key = os.getenv(env_var)
        if key and key.strip() and key.strip() != "your_virustotal_api_key_here":
            return key.strip()

    return None


def get_url_id(url: str) -> str:
    """Generate VirusTotal API v3 URL identifier (base64url encoded without padding)."""
    return base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').rstrip("=")


def query_virustotal_url(url: str, api_key: Optional[str] = None, timeout: int = 6) -> Dict[str, Any]:
    """Query VirusTotal API v3 for an individual URL reputation report.
    
    Args:
        url (str): Target URL to inspect.
        api_key (Optional[str]): VT API key. If omitted, fetched automatically.
        timeout (int): Request timeout in seconds.
        
    Returns:
        Dict[str, Any]: Structured VirusTotal analysis findings.
    """
    if not url or not isinstance(url, str):
        return _make_unavailable_response(url, "Invalid URL format")

    clean_target = url.strip()

    # Check memory cache first
    if clean_target in _MEMORY_CACHE:
        return _MEMORY_CACHE[clean_target]

    vt_key = api_key or get_vt_api_key()
    if not vt_key:
        resp = _make_unavailable_response(
            clean_target,
            "VirusTotal API key not configured. Set VT_API_KEY in .env or Streamlit secrets."
        )
        return resp

    url_id = get_url_id(clean_target)
    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": vt_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(api_endpoint, headers=headers, timeout=timeout)
        
        # HTTP 200: Existing report found
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            timeout_cnt = int(stats.get("timeout", 0))
            reputation = int(attributes.get("reputation", 0))
            
            # Formulate clear status and classification
            if malicious > 0:
                status = "malicious"
                classification = "🔴 Malicious"
            elif suspicious > 0:
                status = "suspicious"
                classification = "🟠 Suspicious"
            elif harmless > 0 or undetected > 0:
                status = "harmless" if harmless > 0 else "undetected"
                classification = "🟢 No malicious detections reported" if harmless > 0 else "⚪ Undetected"
            else:
                status = "undetected"
                classification = "⚪ Undetected"

            permalink = f"https://www.virustotal.com/gui/url/{url_id}"

            result = {
                "url": clean_target,
                "status": status,
                "classification": classification,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "timeout": timeout_cnt,
                "reputation": reputation,
                "permalink": permalink,
                "error_message": None
            }
            _MEMORY_CACHE[clean_target] = result
            return result

        # HTTP 404: URL not yet scanned in VirusTotal database
        elif response.status_code == 404:
            result = {
                "url": clean_target,
                "status": "not_found",
                "classification": "⚪ Not analyzed in VirusTotal database yet",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "timeout": 0,
                "reputation": 0,
                "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                "error_message": "URL not found in VirusTotal cache."
            }
            _MEMORY_CACHE[clean_target] = result
            return result

        # HTTP 429: Rate limit
        elif response.status_code == 429:
            return _make_unavailable_response(
                clean_target, "VirusTotal API rate limit reached (Free tier: 4 req/min)."
            )

        # HTTP 401 / 403: Invalid authentication
        elif response.status_code in [401, 403]:
            return _make_unavailable_response(
                clean_target, "Invalid or unauthorized VirusTotal API key."
            )

        else:
            return _make_unavailable_response(
                clean_target, f"VirusTotal API returned HTTP status {response.status_code}."
            )

    except requests.exceptions.Timeout:
        return _make_unavailable_response(clean_target, "VirusTotal API request timed out.")
    except requests.exceptions.RequestException as e:
        return _make_unavailable_response(clean_target, f"Network error connecting to VirusTotal: {e}")
    except Exception as e:
        return _make_unavailable_response(clean_target, f"Unexpected error during VirusTotal lookup: {e}")


def _make_unavailable_response(url: str, error_msg: str) -> Dict[str, Any]:
    """Helper to build a standardized unavailable/error response."""
    return {
        "url": url,
        "status": "unavailable",
        "classification": "⚠️ Analysis Unavailable",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 0,
        "reputation": 0,
        "permalink": None,
        "error_message": error_msg
    }


def analyze_urls_with_virustotal(urls: List[str], api_key: Optional[str] = None) -> Dict[str, Any]:
    """Analyze a list of unique URLs using VirusTotal and return aggregated summary.
    
    Args:
        urls (List[str]): List of URLs to check.
        api_key (Optional[str]): Optional VirusTotal API key override.
        
    Returns:
        Dict[str, Any]: Aggregated summary and detailed list of findings.
    """
    if not urls:
        return {
            "urls_detected": 0,
            "urls_analyzed": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "clean_count": 0,
            "unavailable_count": 0,
            "results": [],
            "summary_text": "No URLs detected in this email."
        }

    # Remove duplicates while preserving order
    unique_urls = list(dict.fromkeys(urls))
    results: List[Dict[str, Any]] = []

    malicious_count = 0
    suspicious_count = 0
    clean_count = 0
    unavailable_count = 0

    for u in unique_urls:
        res = query_virustotal_url(u, api_key=api_key)
        results.append(res)
        
        if res.get("malicious", 0) > 0:
            malicious_count += 1
        elif res.get("suspicious", 0) > 0:
            suspicious_count += 1
        elif res.get("status") == "harmless" or res.get("harmless", 0) > 0:
            clean_count += 1
        elif res.get("status") == "unavailable":
            unavailable_count += 1

    return {
        "urls_detected": len(unique_urls),
        "urls_analyzed": len(results),
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "clean_count": clean_count,
        "unavailable_count": unavailable_count,
        "results": results
    }
