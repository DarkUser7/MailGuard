"""Prompt templates for Gemini AI report generation."""

from typing import Optional, Dict, Any


SYSTEM_PROMPT = """You are an Email Security Report Assistant for MailGuard AI.

Your job is to explain the results of an existing machine-learning email spam detector, rule-based threat analyzers, and VirusTotal URL threat intelligence.

IMPORTANT RULES:
- Do NOT change or override the ML classification.
- Do NOT invent indicators, URL detections, or VirusTotal results that are not present in the provided analysis.
- If VirusTotal reported 0 malicious detections, state 'No malicious detections reported by VirusTotal' rather than declaring the URL definitively safe.
- If VirusTotal analysis was unavailable or not found, explicitly mention 'Analysis unavailable' or 'Not found in database'.
- Do NOT include markdown headers with #.
- Use plain text with numbered lists and clear section labels.

Clearly structure your report into these sections:
1. CLASSIFICATION SUMMARY - Brief statement of the ML verdict and model confidence
2. DETECTED ISSUES - List all security indicators found (URLs, VirusTotal reputation, keywords, patterns, and email header anomalies)
3. ANALYSIS - Explain why these indicators, URLs, and authentication checks are concerning
4. RISK INTERPRETATION - Explain what the risk score and risk level mean for the recipient
5. RECOMMENDED ACTIONS - Specific, actionable remediation advice for the user

Keep the explanation concise, professional, and understandable to a normal user who is not technical.
"""


def build_report_prompt(
    ml_result: Dict[str, Any],
    url_analysis: Dict[str, Any],
    keyword_analysis: Dict[str, Any],
    pattern_analysis: Dict[str, Any],
    risk_result: Dict[str, Any],
    header_analysis: Optional[Dict[str, Any]] = None,
    vt_analysis: Optional[Dict[str, Any]] = None
) -> str:
    """Build structured prompt for Gemini report generation including VirusTotal intelligence."""
    # Format found keywords
    keyword_details = []
    found = keyword_analysis.get('found_keywords', {})
    for category, words in found.items():
        if words:
            keyword_details.append(f"  {category.upper()}: {', '.join(words)}")
    keyword_str = '\n'.join(keyword_details) if keyword_details else '  None detected'
    
    # Format heuristic suspicious URLs
    suspicious_urls = url_analysis.get('suspicious_urls', [])
    url_details = []
    for u in suspicious_urls:
        if isinstance(u, dict):
            url_details.append(f"  - {u.get('url')} (Reasons: {', '.join(u.get('reasons', []))})")
        else:
            url_details.append(f"  - {u}")
    url_str = '\n'.join(url_details) if url_details else '  None detected'

    # Format VirusTotal Intelligence
    vt_str = "  No URLs analyzed on VirusTotal."
    if vt_analysis and vt_analysis.get('results'):
        vt_lines = [
            f"  Total URLs Checked: {vt_analysis.get('urls_detected', 0)}",
            f"  Malicious URLs: {vt_analysis.get('malicious_count', 0)}",
            f"  Suspicious URLs: {vt_analysis.get('suspicious_count', 0)}",
            "  VirusTotal URL Details:"
        ]
        for res in vt_analysis['results']:
            url = res.get('url')
            status = res.get('classification', res.get('status'))
            mal = res.get('malicious', 0)
            susp = res.get('suspicious', 0)
            harm = res.get('harmless', 0)
            undet = res.get('undetected', 0)
            err = res.get('error_message')
            if err:
                vt_lines.append(f"    - URL: {url} | Status: {status} ({err})")
            else:
                vt_lines.append(
                    f"    - URL: {url} | Status: {status} "
                    f"(Detections: {mal} malicious, {susp} suspicious, {harm} harmless, {undet} undetected)"
                )
        vt_str = '\n'.join(vt_lines)
    
    # Format contributing factors
    factors = risk_result.get('contributing_factors', [])
    factor_details = []
    for f in factors:
        factor_details.append(f"  - {f['factor']}: +{f['points']} points - {f['description']}")
    factor_str = '\n'.join(factor_details) if factor_details else '  None'
    
    # Format pattern findings
    patterns = pattern_analysis.get('patterns_found', [])
    pattern_str = '\n'.join(f'  - {p}' for p in patterns) if patterns else '  None detected'

    # Format header analysis
    header_str = "  No raw headers provided."
    if header_analysis and header_analysis.get('has_headers', False):
        auth = header_analysis.get('auth_results', {})
        sender = header_analysis.get('sender_info', {})
        header_lines = [
            f"  From: {sender.get('from_email', 'N/A')}",
            f"  Return-Path: {sender.get('return_path', 'N/A')}",
            f"  SPF: {auth.get('spf', 'NONE')} | DKIM: {auth.get('dkim', 'NONE')} | DMARC: {auth.get('dmarc', 'NONE')}",
            f"  Sender Spoofing Detected: {'YES (High Risk)' if header_analysis.get('spoofing_detected') else 'No'}",
            f"  Originating IPs: {', '.join(header_analysis.get('origin_ips', [])) or 'None extracted'}",
            f"  Mailer / User-Agent: {header_analysis.get('x_mailer', 'N/A')}"
        ]
        if header_analysis.get('anomalies'):
            header_lines.append("  Header Anomalies:")
            for a in header_analysis['anomalies']:
                header_lines.append(f"    - {a}")
        header_str = '\n'.join(header_lines)
    
    prompt = f"""Analyze the following email security scan results and generate a structured security report.

ML PREDICTION RESULTS:
  Classification: {ml_result.get('prediction', 'unknown').upper()}
  Spam Probability: {ml_result.get('spam_probability', 0):.2%}
  Ham Probability: {ml_result.get('ham_probability', 0):.2%}
  Model Confidence: {ml_result.get('confidence', 0):.2%}

VIRUSTOTAL URL REPUTATION ANALYSIS:
{vt_str}

HEURISTIC URL ANALYSIS:
  Total URLs found: {url_analysis.get('url_count', 0)}
  Suspicious URLs (Heuristics): {url_analysis.get('suspicious_url_count', 0)}
  Details:
{url_str}

KEYWORD ANALYSIS:
  Urgency indicators: {keyword_analysis.get('urgency_count', 0)}
  Financial keywords: {keyword_analysis.get('financial_count', 0)}
  Threat keywords: {keyword_analysis.get('threat_count', 0)}
  Action keywords: {keyword_analysis.get('action_count', 0)}
  Found keywords:
{keyword_str}

PATTERN ANALYSIS:
  Detected patterns:
{pattern_str}

EMAIL HEADER SECURITY CHECKS:
{header_str}

RISK ASSESSMENT:
  Risk Score: {risk_result.get('risk_score', 0)}/100
  Risk Level: {risk_result.get('risk_level', 'UNKNOWN')}
  Contributing Factors:
{factor_str}

Generate a clear, professional security report with these sections:
1. CLASSIFICATION SUMMARY
2. DETECTED ISSUES
3. ANALYSIS
4. RISK INTERPRETATION
5. RECOMMENDED ACTIONS"""
    
    return prompt
