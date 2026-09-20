import re
from typing import Dict, Any, List

class PatternAnalyzer:
    """
    Analyzes text for suspicious formatting, structure, and anomaly patterns.
    """
    
    EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    MONEY_REGEX = re.compile(r'\$\d+(?:,\d{3})*(?:\.\d{2})?|\b\d+(?:,\d{3})*(?:\.\d{2})?\s*(?:dollars|USD)\b', re.IGNORECASE)
    PHONE_REGEX = re.compile(r'\+?\d{1,3}?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
    HTML_REGEX = re.compile(r'<[^>]+>')
    REPEATED_PUNC_REGEX = re.compile(r'([!?$*])\1{2,}')

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze text for structural anomalies and specific data formats.
        
        Args:
            text (str): The text content to analyze.
            
        Returns:
            Dict[str, Any]: Results containing identified patterns and anomalies.
        """
        if not isinstance(text, str):
            text = str(text)
            
        # Capitalization check
        alpha_chars = [c for c in text if c.isalpha()]
        total_alpha = len(alpha_chars)
        upper_chars = sum(1 for c in alpha_chars if c.isupper())
        
        caps_percentage = (upper_chars / total_alpha) * 100 if total_alpha > 0 else 0.0
        excessive_caps = caps_percentage > 30.0 and len(text) > 20
        
        # Punctuation check
        exclamation_count = text.count('!')
        repeated_punctuation = self.REPEATED_PUNC_REGEX.findall(text)
        repeated_punctuation_count = len(repeated_punctuation)
        excessive_punctuation = repeated_punctuation_count > 0 or exclamation_count > 5
        
        # HTML check
        has_html = bool(self.HTML_REGEX.search(text))
        
        # Data extraction
        money_references = list(set(self.MONEY_REGEX.findall(text)))
        phone_numbers = list(set(self.PHONE_REGEX.findall(text)))
        email_addresses = list(set(self.EMAIL_REGEX.findall(text)))
        
        # Only true threat anomalies count towards threat indicators
        suspicious_patterns = []
        if excessive_caps:
            suspicious_patterns.append("Excessive capitalization")
        if excessive_punctuation:
            suspicious_patterns.append("Excessive or repeated punctuation")
            
        all_patterns = list(suspicious_patterns)
        if has_html:
            all_patterns.append("Contains HTML formatting")
        if money_references:
            all_patterns.append("Contains monetary references")
        if phone_numbers:
            all_patterns.append("Contains contact phone numbers")
        
        return {
            'caps_percentage': round(caps_percentage, 2),
            'excessive_caps': excessive_caps,
            'exclamation_count': exclamation_count,
            'excessive_punctuation': excessive_punctuation,
            'repeated_punctuation_count': repeated_punctuation_count,
            'has_html': has_html,
            'money_references': money_references,
            'phone_numbers': phone_numbers,
            'email_addresses': email_addresses,
            'suspicious_patterns': suspicious_patterns,
            'suspicious_pattern_count': len(suspicious_patterns),
            'patterns_found': suspicious_patterns  # Keep only threat patterns in patterns_found for count
        }
