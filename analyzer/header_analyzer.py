"""Email Header Security Analyzer.

Parses RFC 822 / 5322 raw email headers to detect:
- SPF / DKIM / DMARC authentication verdicts
- Sender domain alignment and spoofing detection
- Originating IP extraction & relay anomalies
- Suspicious mailer software (X-Mailer / User-Agent)
- Missing / malformed RFC compliance headers (Message-ID, Date, etc.)
"""

import re
import email
from email.utils import parseaddr
from typing import Dict, Any, List, Optional


class HeaderAnalyzer:
    """Analyzes raw email headers for phishing, spoofing, and authentication anomalies."""

    def __init__(self):
        # Known mass mailer signatures
        self.suspicious_mailers = [
            'phpmailer', 'massmail', 'darkmailer', 'direct email',
            'super email', 'group mail', 'atomic mailer', 'turbo mailer',
            'e-mail sender', 'sendblaster', 'mailer-daemon'
        ]
        
        # Known legitimate parent/subsidiary domain alignments
        self.known_ecosystems = {
            'youtube.com': {'google.com', 'youtube.com', 'googlemail.com'},
            'google.com': {'google.com', 'youtube.com', 'googlemail.com', 'googlegroups.com'},
            'gmail.com': {'google.com', 'gmail.com', 'googlemail.com'},
            'github.com': {'github.com', 'githubmail.com'},
            'microsoft.com': {'microsoft.com', 'office365.com', 'outlook.com', 'microsoftonline.com'},
            'apple.com': {'apple.com', 'icloud.com'},
            'amazon.com': {'amazon.com', 'amazonses.com', 'amazon-support.com'}
        }

    def analyze(self, header_text: str) -> Dict[str, Any]:
        """Analyze raw email headers and return structured security findings.
        
        Args:
            header_text (str): Raw email header string (or full raw .eml content).
            
        Returns:
            Dict[str, Any]: Structured security analysis of email headers.
        """
        if not header_text or not header_text.strip():
            return {
                'has_headers': False,
                'status': 'NO_HEADERS_PROVIDED',
                'summary': 'No raw headers provided for analysis.',
                'anomalies': [],
                'auth_results': {'spf': 'NONE', 'dkim': 'NONE', 'dmarc': 'NONE'},
                'extracted_headers': {},
                'spoofing_detected': False,
                'risk_points': 0
            }

        # Parse headers using standard email parser
        msg = email.message_from_string(header_text)
        
        # Extract primary headers
        from_header = msg.get('From', '')
        to_header = msg.get('To', '')
        subject_header = msg.get('Subject', '')
        date_header = msg.get('Date', '')
        return_path = msg.get('Return-Path', '')
        reply_to = msg.get('Reply-To', '')
        message_id = msg.get('Message-ID', '')
        x_mailer = msg.get('X-Mailer', '') or msg.get('User-Agent', '')
        received_spf = msg.get('Received-SPF', '')
        auth_results = msg.get_all('Authentication-Results', [])
        received_hops = msg.get_all('Received', [])

        anomalies: List[str] = []
        risk_points = 0

        # 1. Parse Authentication Checks (SPF, DKIM, DMARC)
        spf_verdict = self._parse_spf(received_spf, auth_results)
        dkim_verdict = self._parse_dkim(msg, auth_results)
        dmarc_verdict = self._parse_dmarc(auth_results)

        if spf_verdict == 'FAIL':
            risk_points += 25
            anomalies.append("SPF Authentication FAIL: Sending IP is not authorized by the sender's DNS domain.")
        elif spf_verdict == 'SOFTFAIL':
            risk_points += 15
            anomalies.append("SPF Authentication SOFTFAIL: Sending IP is suspect and discouraged by sender policy.")

        if dkim_verdict == 'FAIL':
            risk_points += 20
            anomalies.append("DKIM Authentication FAIL: Cryptographic signature is invalid or email was tampered in transit.")

        if dmarc_verdict == 'FAIL':
            risk_points += 25
            anomalies.append("DMARC Policy FAIL: Email failed domain alignment and security enforcement policy.")

        # 2. Parse Sender & Domain Alignment (Intelligent Spoofing Detection)
        from_name, from_email = parseaddr(from_header)
        return_name, return_email = parseaddr(return_path)
        reply_name, reply_email = parseaddr(reply_to)

        from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
        return_domain = return_email.split('@')[-1].lower() if '@' in return_email else ''
        reply_domain = reply_email.split('@')[-1].lower() if '@' in reply_email else ''

        # Base domain extractor (e.g. scoutcamp.bounces.google.com -> google.com)
        from_root = self._get_root_domain(from_domain)
        return_root = self._get_root_domain(return_domain)

        spoofing_detected = False

        if from_domain and return_domain and from_domain != return_domain:
            # Check if domains belong to the same verified ecosystem (e.g. youtube.com & google.com)
            is_ecosystem_aligned = False
            if from_root in self.known_ecosystems and return_root in self.known_ecosystems[from_root]:
                is_ecosystem_aligned = True
            elif from_root == return_root and from_root != '':
                is_ecosystem_aligned = True

            # If DMARC passed or SPF+DKIM passed on verified ecosystem -> Legitimate delivery, NOT spoofing!
            if (dmarc_verdict == 'PASS' or (spf_verdict == 'PASS' and dkim_verdict == 'PASS')) and is_ecosystem_aligned:
                spoofing_detected = False
            elif dmarc_verdict == 'FAIL' or spf_verdict in ['FAIL', 'SOFTFAIL'] or not is_ecosystem_aligned:
                # True spoofing or unaligned external bounce
                if not (dmarc_verdict == 'PASS'):
                    spoofing_detected = True
                    risk_points += 30
                    anomalies.append(
                        f"Domain Mismatch (Potential Spoofing): 'From' domain ({from_domain}) "
                        f"differs from 'Return-Path' domain ({return_domain})."
                    )

        if from_domain and reply_domain and from_domain != reply_domain:
            reply_root = self._get_root_domain(reply_domain)
            if from_root != reply_root:
                anomalies.append(
                    f"Reply-To Mismatch: Responses will be directed to external domain ({reply_domain}) "
                    f"instead of sender ({from_domain})."
                )
                risk_points += 15

        # 3. Originating IP & Relay Hop Analysis
        origin_ips = self._extract_origin_ips(received_hops)
        if origin_ips:
            for ip in origin_ips:
                if self._is_suspicious_ip(ip):
                    anomalies.append(f"Suspicious Originating IP detected: {ip}")
                    risk_points += 10

        # 4. Mailer / Client Analysis
        if x_mailer:
            for bad_mailer in self.suspicious_mailers:
                if bad_mailer in x_mailer.lower():
                    risk_points += 15
                    anomalies.append(f"Suspicious Mass Mailer Software detected: '{x_mailer}'")
                    break

        # 5. Missing Core Headers Check
        if not message_id:
            risk_points += 10
            anomalies.append("Missing 'Message-ID' header (unusual for standard mail transfer agents).")

        if not from_header:
            risk_points += 20
            anomalies.append("Missing 'From' header.")

        # Construct status summary
        header_risk_level = 'LOW'
        if risk_points >= 40:
            header_risk_level = 'CRITICAL'
        elif risk_points >= 25:
            header_risk_level = 'HIGH'
        elif risk_points >= 10:
            header_risk_level = 'MEDIUM'

        return {
            'has_headers': True,
            'header_risk_score': min(risk_points, 100),
            'header_risk_level': header_risk_level,
            'spoofing_detected': spoofing_detected,
            'auth_results': {
                'spf': spf_verdict,
                'dkim': dkim_verdict,
                'dmarc': dmarc_verdict
            },
            'sender_info': {
                'from_email': from_email,
                'from_name': from_name,
                'from_domain': from_domain,
                'return_path': return_email,
                'reply_to': reply_email
            },
            'origin_ips': origin_ips,
            'hop_count': len(received_hops),
            'x_mailer': x_mailer or 'Not specified',
            'message_id': message_id or 'Missing',
            'subject': subject_header or 'No Subject',
            'date': date_header or 'No Date',
            'anomalies': anomalies,
            'raw_headers_length': len(header_text)
        }

    def _get_root_domain(self, domain: str) -> str:
        """Extract root domain (e.g. scoutcamp.bounces.google.com -> google.com)."""
        if not domain:
            return ""
        parts = domain.strip().lower().split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain

    def _parse_spf(self, received_spf: str, auth_results: List[str]) -> str:
        """Extract SPF verdict."""
        combined = (received_spf + " " + " ".join(auth_results)).lower()
        if 'spf=pass' in combined or received_spf.lower().startswith('pass'):
            return 'PASS'
        if 'spf=fail' in combined or received_spf.lower().startswith('fail') or 'spf=hardfail' in combined:
            return 'FAIL'
        if 'spf=softfail' in combined or received_spf.lower().startswith('softfail'):
            return 'SOFTFAIL'
        if 'spf=neutral' in combined or 'spf=none' in combined:
            return 'NEUTRAL'
        return 'NONE'

    def _parse_dkim(self, msg: email.message.Message, auth_results: List[str]) -> str:
        """Extract DKIM verdict."""
        combined = " ".join(auth_results).lower()
        if 'dkim=pass' in combined:
            return 'PASS'
        if 'dkim=fail' in combined:
            return 'FAIL'
        if msg.get('DKIM-Signature'):
            return 'PRESENT'
        return 'NONE'

    def _parse_dmarc(self, auth_results: List[str]) -> str:
        """Extract DMARC verdict."""
        combined = " ".join(auth_results).lower()
        if 'dmarc=pass' in combined:
            return 'PASS'
        if 'dmarc=fail' in combined:
            return 'FAIL'
        return 'NONE'

    def _extract_origin_ips(self, received_hops: List[str]) -> List[str]:
        """Extract originating IP addresses from Received hops."""
        ips = []
        ip_pattern = r'\[?(\b(?:\d{1,3}\.){3}\d{1,3}\b)\]?'
        for hop in received_hops:
            matches = re.findall(ip_pattern, hop)
            for m in matches:
                if m not in ips and not m.startswith('127.'):
                    ips.append(m)
        return ips

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check for reserved/bogon ranges appearing in external hops."""
        if ip in ['0.0.0.0', '255.255.255.255']:
            return True
        return False
