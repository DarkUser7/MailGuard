from typing import Dict, Any, Optional, List

class RiskEngine:
    """
    Calculates an overall risk score (0-100) based on inputs from various security analyzers,
    including heuristic checks, email headers, and VirusTotal threat intelligence.
    The ML model prediction remains independent and untouched.
    """

    def calculate_risk(
        self,
        ml_result: Dict[str, Any],
        url_analysis: Dict[str, Any], 
        keyword_analysis: Dict[str, Any],
        pattern_analysis: Dict[str, Any],
        header_analysis: Optional[Dict[str, Any]] = None,
        vt_analysis: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Calculate risk score using a weighted system based on various analysis results.
        
        Args:
            ml_result (Dict): Results from the machine learning model.
            url_analysis (Dict): Results from URLAnalyzer.
            keyword_analysis (Dict): Results from KeywordAnalyzer.
            pattern_analysis (Dict): Results from PatternAnalyzer.
            header_analysis (Optional[Dict]): Results from HeaderAnalyzer.
            vt_analysis (Optional[Dict]): Results from VirusTotal URL intelligence.
            
        Returns:
            Dict[str, Any]: Total risk score, category, and contributing factors.
        """
        score = 0
        contributing_factors = []
        
        # 1. VirusTotal URL Intelligence (Highest confidence external threat data)
        if vt_analysis and vt_analysis.get('malicious_count', 0) > 0:
            m_cnt = vt_analysis['malicious_count']
            score += 35
            contributing_factors.append({
                'factor': 'VirusTotal Malicious URL Detected',
                'points': 35,
                'description': f"{m_cnt} URL(s) confirmed as malicious by global security engines on VirusTotal."
            })
        elif vt_analysis and vt_analysis.get('suspicious_count', 0) > 0:
            s_cnt = vt_analysis['suspicious_count']
            score += 20
            contributing_factors.append({
                'factor': 'VirusTotal Suspicious URL Detected',
                'points': 20,
                'description': f"{s_cnt} URL(s) flagged with suspicious reputation on VirusTotal."
            })

        # 2. Heuristic URL checks (+25 if not already covered by VT)
        if url_analysis.get('suspicious_url_count', 0) > 0:
            # If VT didn't already flag it, add heuristic points
            pts = 20 if (vt_analysis and vt_analysis.get('malicious_count', 0) > 0) else 30
            score += pts
            contributing_factors.append({
                'factor': 'Heuristic Suspicious URLs',
                'points': pts,
                'description': f"Found {url_analysis['suspicious_url_count']} URL(s) with suspicious structure/shortener/IP patterns."
            })
            
        # 3. Keyword checks
        if keyword_analysis.get('urgency_count', 0) > 0:
            score += 20
            contributing_factors.append({
                'factor': 'Urgency Keywords',
                'points': 20,
                'description': "Contains language creating a false sense of urgency."
            })
            
        if keyword_analysis.get('financial_count', 0) > 0:
            score += 20
            contributing_factors.append({
                'factor': 'Financial Keywords',
                'points': 20,
                'description': "Contains financial lures or reward references."
            })
            
        if keyword_analysis.get('threat_count', 0) > 0:
            score += 15
            contributing_factors.append({
                'factor': 'Threat Keywords',
                'points': 15,
                'description': "Contains threatening language (e.g., account suspension)."
            })
            
        if keyword_analysis.get('action_count', 0) > 0:
            score += 10
            contributing_factors.append({
                'factor': 'Action Keywords',
                'points': 10,
                'description': "Prompts for immediate action or credential entry."
            })
            
        # 4. Pattern checks
        if pattern_analysis.get('excessive_caps', False):
            score += 10
            contributing_factors.append({
                'factor': 'Excessive Capitalization',
                'points': 10,
                'description': "Unusually high percentage of uppercase text."
            })
            
        if pattern_analysis.get('excessive_punctuation', False):
            score += 5
            contributing_factors.append({
                'factor': 'Excessive Punctuation',
                'points': 5,
                'description': "Suspicious use of repeated punctuation (e.g. !!!)."
            })

        # 5. Header Security checks (if headers provided)
        if header_analysis and header_analysis.get('has_headers', False):
            if header_analysis.get('spoofing_detected', False):
                score += 30
                contributing_factors.append({
                    'factor': 'Sender Spoofing (Header Mismatch)',
                    'points': 30,
                    'description': "From address domain does not align with Return-Path envelope."
                })
            
            auth_results = header_analysis.get('auth_results', {})
            if auth_results.get('spf') in ['FAIL', 'SOFTFAIL']:
                pts = 25 if auth_results.get('spf') == 'FAIL' else 15
                score += pts
                contributing_factors.append({
                    'factor': f"SPF Authentication ({auth_results.get('spf')})",
                    'points': pts,
                    'description': "Sending mail server is not authorized to send on behalf of the domain."
                })
                
            if auth_results.get('dkim') == 'FAIL':
                score += 20
                contributing_factors.append({
                    'factor': 'DKIM Verification Failed',
                    'points': 20,
                    'description': "Cryptographic signature validation failed or email modified in transit."
                })

            if auth_results.get('dmarc') == 'FAIL':
                score += 25
                contributing_factors.append({
                    'factor': 'DMARC Policy Failed',
                    'points': 25,
                    'description': "Email failed receiver DMARC compliance checks."
                })
            
        # 6. ML check
        spam_prob = ml_result.get('spam_probability', 0.0)
        if spam_prob > 0.8:
            score += 15
            contributing_factors.append({
                'factor': 'ML Model Confidence',
                'points': 15,
                'description': f"Machine learning model indicated high probability ({spam_prob:.2f}) of spam/phishing."
            })
            
        # Cap score at 100
        score = min(score, 100)
        
        # Determine risk level
        if score <= 20:
            level = 'LOW'
        elif score <= 50:
            level = 'MEDIUM'
        elif score <= 75:
            level = 'HIGH'
        else:
            level = 'CRITICAL'
            
        return {
            'risk_score': score,
            'risk_level': level,
            'contributing_factors': contributing_factors
        }
