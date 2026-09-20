import re
from typing import Dict, Any, List

class KeywordAnalyzer:
    """
    Analyzes text for common phishing, spam, and scam keywords/phrases categorized by intent.
    """
    
    CATEGORIES = {
        'urgency': [
            'urgent', 'immediately', 'act now', 'limited time', 'expire', 
            'hurry', "don't delay", 'right away', 'fast', 'quick', 'deadline', 
            'last chance', 'final notice', 'time sensitive', 'expiring'
        ],
        'financial': [
            'free', 'winner', 'won', 'prize', 'cash', 'money', 'credit card', 
            'bank account', 'investment', 'income', 'earn', 'profit', 'million', 
            'billion', 'lottery', 'jackpot', 'bonus', 'discount', 'offer', 'deal'
        ],
        'threat': [
            'suspended', 'terminated', 'unauthorized', 'verify your account', 
            'confirm your identity', 'locked', 'disabled', 'compromised', 'breach', 
            'illegal', 'violation', 'penalty', 'legal action', 'arrest', 'warrant'
        ],
        'action': [
            'click here', 'click below', 'click now', 'download', 'open attachment', 
            'log in', 'sign in', 'update your', 'confirm now', 'verify now', 
            'claim your', 'redeem', 'activate', 'subscribe', 'unsubscribe'
        ]
    }

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Scan the text for suspicious phrases across predefined categories.
        
        Args:
            text (str): The text content to analyze.
            
        Returns:
            Dict[str, Any]: Analysis results with counts and identified keywords.
        """
        if not isinstance(text, str):
            text = str(text)
            
        text_lower = text.lower()
        
        found_keywords = {
            'urgency': [],
            'financial': [],
            'threat': [],
            'action': []
        }
        
        # Look for whole word/phrase matches
        for category, phrases in self.CATEGORIES.items():
            for phrase in phrases:
                # Using regex word boundaries for accurate matching
                pattern = r'\b' + re.escape(phrase) + r'\b'
                if re.search(pattern, text_lower):
                    found_keywords[category].append(phrase)
                    
        urgency_count = len(found_keywords['urgency'])
        financial_count = len(found_keywords['financial'])
        threat_count = len(found_keywords['threat'])
        action_count = len(found_keywords['action'])
        
        total_suspicious = urgency_count + financial_count + threat_count + action_count
        
        return {
            'urgency_count': urgency_count,
            'financial_count': financial_count,
            'threat_count': threat_count,
            'action_count': action_count,
            'total_suspicious_keywords': total_suspicious,
            'found_keywords': found_keywords
        }
