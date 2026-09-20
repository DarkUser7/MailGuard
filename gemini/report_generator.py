"""Report generator combining ML results + analysis into Gemini-powered reports."""

from datetime import datetime
from typing import Optional, Dict, Any
from .client import GeminiClient
from .prompts import SYSTEM_PROMPT, build_report_prompt


class ReportGenerator:
    """Generates security reports using Gemini AI with fallback."""
    
    def __init__(self):
        self.gemini = GeminiClient()
    
    def generate_report(
        self,
        ml_result: Dict[str, Any],
        url_analysis: Dict[str, Any],
        keyword_analysis: Dict[str, Any],
        pattern_analysis: Dict[str, Any],
        risk_result: Dict[str, Any],
        header_analysis: Optional[Dict[str, Any]] = None,
        vt_analysis: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate a complete security report including VirusTotal threat intelligence.
        
        Uses Gemini if available, otherwise falls back to template.
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'ml_result': ml_result,
            'url_analysis': url_analysis,
            'keyword_analysis': keyword_analysis,
            'pattern_analysis': pattern_analysis,
            'header_analysis': header_analysis or {'has_headers': False},
            'vt_analysis': vt_analysis or {'urls_detected': 0, 'results': []},
            'risk_result': risk_result,
            'source': 'gemini',
            'report_text': ''
        }
        
        if self.gemini.is_available():
            try:
                prompt = build_report_prompt(
                    ml_result=ml_result,
                    url_analysis=url_analysis,
                    keyword_analysis=keyword_analysis,
                    pattern_analysis=pattern_analysis,
                    risk_result=risk_result,
                    header_analysis=header_analysis,
                    vt_analysis=vt_analysis
                )
                report['report_text'] = self.gemini.generate(prompt, SYSTEM_PROMPT)
                report['source'] = 'gemini'
                return report
            except Exception as e:
                print(f"Gemini report generation failed: {e}. Using fallback.")
        
        # Fallback to template-based report
        report['report_text'] = self._generate_fallback_report(
            ml_result=ml_result,
            url_analysis=url_analysis,
            keyword_analysis=keyword_analysis,
            pattern_analysis=pattern_analysis,
            risk_result=risk_result,
            header_analysis=header_analysis,
            vt_analysis=vt_analysis
        )
        report['source'] = 'template'
        return report
    
    def _generate_fallback_report(
        self,
        ml_result: Dict[str, Any],
        url_analysis: Dict[str, Any],
        keyword_analysis: Dict[str, Any],
        pattern_analysis: Dict[str, Any],
        risk_result: Dict[str, Any],
        header_analysis: Optional[Dict[str, Any]] = None,
        vt_analysis: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate a template-based report when Gemini is unavailable."""
        prediction = ml_result.get('prediction', 'unknown').upper()
        spam_prob = ml_result.get('spam_probability', 0)
        risk_score = risk_result.get('risk_score', 0)
        risk_level = risk_result.get('risk_level', 'UNKNOWN')
        
        # Build detected issues list
        issues = []

        # 1. VirusTotal Findings
        if vt_analysis and vt_analysis.get('results'):
            for res in vt_analysis['results']:
                url = res.get('url')
                mal = res.get('malicious', 0)
                susp = res.get('suspicious', 0)
                if mal > 0:
                    issues.append(f"VirusTotal Confirmed Malicious URL: {url} ({mal} security engines flagged)")
                elif susp > 0:
                    issues.append(f"VirusTotal Suspicious URL: {url} ({susp} security engines flagged)")
                elif res.get('status') == 'harmless' or res.get('harmless', 0) > 0:
                    issues.append(f"VirusTotal Reputation Check: {url} (No malicious detections reported)")
                elif res.get('error_message'):
                    issues.append(f"VirusTotal URL Check ({url}): {res.get('error_message')}")
        
        # 2. Heuristic URLs
        if url_analysis.get('suspicious_url_count', 0) > 0:
            issues.append(f"Heuristic suspicious URL patterns detected: {url_analysis['suspicious_url_count']}")
        
        # 3. Keywords
        found_kw = keyword_analysis.get('found_keywords', {})
        if found_kw.get('urgency'):
            issues.append(f"Urgency language: {', '.join(found_kw['urgency'])}")
        if found_kw.get('financial'):
            issues.append(f"Financial/reward keywords: {', '.join(found_kw['financial'])}")
        if found_kw.get('threat'):
            issues.append(f"Threat indicators: {', '.join(found_kw['threat'])}")
        if found_kw.get('action'):
            issues.append(f"Suspicious action phrases: {', '.join(found_kw['action'])}")
        
        for pattern in pattern_analysis.get('patterns_found', []):
            issues.append(pattern)

        # 4. Header anomalies
        if header_analysis and header_analysis.get('has_headers', False):
            for anomaly in header_analysis.get('anomalies', []):
                issues.append(f"Header Anomaly: {anomaly}")
        
        issues_text = '\n'.join(f'  {i+1}. {issue}' for i, issue in enumerate(issues)) if issues else '  No significant issues detected.'
        
        # Build contributing factors
        factors = risk_result.get('contributing_factors', [])
        factors_text = '\n'.join(
            f'  - {f["factor"]}: +{f["points"]} points' for f in factors
        ) if factors else '  No contributing factors.'
        
        report = f"""EMAIL SECURITY REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'=' * 50}

1. CLASSIFICATION SUMMARY
   The email has been classified as {prediction} by the machine learning model
   with a model spam probability of {spam_prob:.2%}.

2. DETECTED ISSUES
{issues_text}

3. ANALYSIS
   The ML classifier analyzed the email content and determined this email
   {'exhibits characteristics of spam or fraudulent intent' if prediction == 'SPAM' else 'appears to be legitimate correspondence'}.
   Security threat scans and URL intelligence identified the detailed indicators listed above.

4. RISK INTERPRETATION
   Overall Risk Score: {risk_score}/100 ({risk_level})
   Contributing Risk Factors:
{factors_text}

5. RECOMMENDED ACTIONS
   {'- Do not click any links or download attachments.' if (prediction == 'SPAM' or (vt_analysis and vt_analysis.get('malicious_count', 0) > 0)) else '- Follow standard email security practices.'}
   {'- Do not enter personal, financial, or banking credentials.' if prediction == 'SPAM' else ''}
   {'- Verify the sender independently through trusted channels.' if prediction == 'SPAM' else ''}
   {'- Report this email to your organization security team or mail provider.' if prediction == 'SPAM' else ''}
   - Always verify unexpected requests independently.
"""
        return report
