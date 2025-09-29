import re
import json
import requests
import hashlib
import base64
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import dns.resolver
import whois
from email import message_from_string
from email.header import decode_header
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

# Download required NLTK data (run once)
try:
    nltk.data.find('vader_lexicon')
except LookupError:
    nltk.download('vader_lexicon')

@dataclass
class PhishingScore:
    total_score: float
    risk_level: str
    indicators: List[str]
    url_analysis: Dict
    sender_analysis: Dict
    content_analysis: Dict
    attachment_analysis: Dict
    timestamp: str

class PhishingDetector:
    def __init__(self):
        self.sia = SentimentIntensityAnalyzer()
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'rb.gy', 'is.gd'
        ]
        self.trusted_domains = [
            'gmail.com', 'outlook.com', 'yahoo.com', 'apple.com',
            'microsoft.com', 'google.com', 'amazon.com'
        ]
        self.phishing_keywords = [
            'urgent', 'verify', 'suspended', 'confirm', 'update',
            'click here', 'act now', 'limited time', 'expire',
            'unauthorized', 'security alert', 'account locked',
            'winner', 'congratulations', 'claim', 'prize',
            'refund', 'tax refund', 'inheritance', 'lottery'
        ]
        self.suspicious_file_extensions = [
            '.exe', '.scr', '.bat', '.com', '.pif', '.vbs',
            '.js', '.jar', '.zip', '.rar', '.7z'
        ]
        
    def analyze_email(self, email_content: str, sender: str = None, 
                     subject: str = None, attachments: List[str] = None) -> PhishingScore:
        """Main analysis function that returns a comprehensive phishing score"""
        
        total_score = 0
        indicators = []
        
        # Parse email if raw content provided
        if not sender or not subject:
            msg = message_from_string(email_content)
            sender = sender or msg.get('From', '')
            subject = subject or msg.get('Subject', '')
            
        # Analyze different components
        url_analysis = self._analyze_urls(email_content)
        sender_analysis = self._analyze_sender(sender)
        content_analysis = self._analyze_content(email_content, subject)
        attachment_analysis = self._analyze_attachments(attachments or [])
        
        # Calculate scores
        total_score += url_analysis['score']
        total_score += sender_analysis['score']
        total_score += content_analysis['score']
        total_score += attachment_analysis['score']
        
        # Collect indicators
        indicators.extend(url_analysis['indicators'])
        indicators.extend(sender_analysis['indicators'])
        indicators.extend(content_analysis['indicators'])
        indicators.extend(attachment_analysis['indicators'])
        
        # Determine risk level
        risk_level = self._calculate_risk_level(total_score)
        
        return PhishingScore(
            total_score=round(total_score, 2),
            risk_level=risk_level,
            indicators=indicators,
            url_analysis=url_analysis,
            sender_analysis=sender_analysis,
            content_analysis=content_analysis,
            attachment_analysis=attachment_analysis,
            timestamp=datetime.now().isoformat()
        )
    
    def _analyze_urls(self, content: str) -> Dict:
        """Analyze URLs in email content"""
        score = 0
        indicators = []
        urls = []
        
        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        found_urls = re.findall(url_pattern, content)
        
        for url in found_urls:
            url_info = self._analyze_single_url(url)
            urls.append(url_info)
            score += url_info['score']
            indicators.extend(url_info['indicators'])
        
        return {
            'score': score,
            'indicators': indicators,
            'urls_found': len(found_urls),
            'url_details': urls
        }
    
    def _analyze_single_url(self, url: str) -> Dict:
        """Analyze a single URL for suspicious characteristics"""
        score = 0
        indicators = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for URL shorteners
            if any(short_domain in domain for short_domain in self.suspicious_domains):
                score += 3
                indicators.append(f"URL shortener detected: {domain}")
            
            # Check for suspicious patterns
            if len(domain) > 30:
                score += 2
                indicators.append("Unusually long domain name")
            
            if domain.count('-') > 3:
                score += 2
                indicators.append("Multiple hyphens in domain")
            
            if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
                score += 4
                indicators.append("IP address instead of domain name")
            
            # Check for homograph attacks
            suspicious_chars = ['а', 'о', 'е', 'р', 'с', 'х']  # Cyrillic lookalikes
            if any(char in domain for char in suspicious_chars):
                score += 5
                indicators.append("Potential homograph attack")
                
        except Exception as e:
            score += 1
            indicators.append("Malformed URL")
        
        return {
            'url': url,
            'score': score,
            'indicators': indicators
        }
    
    def _analyze_sender(self, sender: str) -> Dict:
        """Analyze sender information"""
        score = 0
        indicators = []
        
        if not sender:
            return {'score': 2, 'indicators': ['No sender information'], 'domain': None}
        
        # Extract domain
        email_match = re.search(r'@([a-zA-Z0-9.-]+)', sender)
        domain = email_match.group(1).lower() if email_match else None
        
        if not domain:
            score += 3
            indicators.append("Invalid sender format")
            return {'score': score, 'indicators': indicators, 'domain': None}
        
        # Check against trusted domains
        if domain in self.trusted_domains:
            score -= 1  # Reduce suspicion for trusted domains
        else:
            # Check for suspicious domain patterns
            if len(domain) < 4:
                score += 2
                indicators.append("Very short domain name")
            
            if domain.count('.') > 3:
                score += 1
                indicators.append("Multiple subdomains")
            
            # Check for numbers in domain
            if re.search(r'\d', domain):
                score += 1
                indicators.append("Numbers in domain name")
        
        # Check for display name spoofing
        if '<' in sender and '>' in sender:
            display_name = sender.split('<')[0].strip()
            if display_name and any(trusted in display_name.lower() for trusted in ['paypal', 'amazon', 'microsoft', 'apple']):
                if domain not in self.trusted_domains:
                    score += 4
                    indicators.append("Display name spoofing detected")
        
        return {
            'score': score,
            'indicators': indicators,
            'domain': domain
        }
    
    def _analyze_content(self, content: str, subject: str) -> Dict:
        """Analyze email content and subject"""
        score = 0
        indicators = []
        
        full_text = (subject + " " + content).lower()
        
        # Check for phishing keywords
        keyword_count = 0
        found_keywords = []
        for keyword in self.phishing_keywords:
            if keyword in full_text:
                keyword_count += 1
                found_keywords.append(keyword)
        
        if keyword_count >= 3:
            score += keyword_count * 1.5
            indicators.append(f"Multiple suspicious keywords: {', '.join(found_keywords[:5])}")
        elif keyword_count > 0:
            score += keyword_count
            indicators.append(f"Suspicious keywords found: {', '.join(found_keywords)}")
        
        # Sentiment analysis
        sentiment = self.sia.polarity_scores(full_text)
        if sentiment['compound'] < -0.5:
            score += 2
            indicators.append("Highly negative sentiment (fear/urgency)")
        
        # Check for excessive punctuation/caps
        exclamation_count = content.count('!')
        if exclamation_count > 5:
            score += 2
            indicators.append("Excessive exclamation marks")
        
        caps_ratio = len(re.findall(r'[A-Z]', content)) / max(len(content), 1)
        if caps_ratio > 0.3:
            score += 2
            indicators.append("Excessive capital letters")
        
        # Check for grammar/spelling issues (simplified)
        grammar_issues = len(re.findall(r'\b\w+\b\s+\b\w+\b\s+\b\w+\b', content))
        if grammar_issues > 10:
            score += 1
            indicators.append("Potential grammar/spelling issues")
        
        return {
            'score': score,
            'indicators': indicators,
            'keyword_count': keyword_count,
            'sentiment': sentiment,
            'found_keywords': found_keywords
        }
    
    def _analyze_attachments(self, attachments: List[str]) -> Dict:
        """Analyze email attachments"""
        score = 0
        indicators = []
        suspicious_attachments = []
        
        for attachment in attachments:
            attachment_lower = attachment.lower()
            
            # Check for suspicious file extensions
            for ext in self.suspicious_file_extensions:
                if attachment_lower.endswith(ext):
                    score += 4
                    indicators.append(f"Suspicious file type: {attachment}")
                    suspicious_attachments.append(attachment)
                    break
            
            # Check for double extensions
            if attachment_lower.count('.') > 1:
                parts = attachment_lower.split('.')
                if len(parts) > 2 and parts[-2] in ['pdf', 'doc', 'jpg']:
                    score += 3
                    indicators.append(f"Double extension detected: {attachment}")
                    suspicious_attachments.append(attachment)
        
        return {
            'score': score,
            'indicators': indicators,
            'total_attachments': len(attachments),
            'suspicious_attachments': suspicious_attachments
        }
    
    def _calculate_risk_level(self, score: float) -> str:
        """Calculate risk level based on total score"""
        if score >= 10:
            return "HIGH"
        elif score >= 6:
            return "MEDIUM"
        elif score >= 3:
            return "LOW"
        else:
            return "SAFE"
    
    def should_quarantine(self, score: PhishingScore) -> bool:
        """Determine if email should be quarantined"""
        return score.risk_level in ["HIGH", "MEDIUM"]
    
    def generate_report(self, score: PhishingScore) -> str:
        """Generate a human-readable report"""
        report = f"""
PHISHING DETECTION REPORT
========================
Timestamp: {score.timestamp}
Total Score: {score.total_score}
Risk Level: {score.risk_level}

ANALYSIS SUMMARY:
- URLs: {score.url_analysis['score']} points ({score.url_analysis['urls_found']} URLs found)
- Sender: {score.sender_analysis['score']} points
- Content: {score.content_analysis['score']} points
- Attachments: {score.attachment_analysis['score']} points

INDICATORS FOUND:
"""
        for i, indicator in enumerate(score.indicators, 1):
            report += f"{i}. {indicator}\n"
        
        if score.risk_level == "HIGH":
            report += "\n⚠️  RECOMMENDATION: QUARANTINE EMAIL IMMEDIATELY"
        elif score.risk_level == "MEDIUM":
            report += "\n⚡ RECOMMENDATION: FLAG FOR REVIEW"
        elif score.risk_level == "LOW":
            report += "\n💡 RECOMMENDATION: MONITOR"
        else:
            report += "\n✅ RECOMMENDATION: SAFE TO DELIVER"
        
        return report

# Example usage and testing
if __name__ == "__main__":
    detector = PhishingDetector()
    
    # Test email samples
    test_emails = [
        {
            "sender": "security@paypaI.com",  # Note the capital I instead of l
            "subject": "URGENT: Account Suspended - Act Now!",
            "content": """
Dear Customer,
            
Your PayPal account has been SUSPENDED due to suspicious activity!
            
Click here immediately to verify your account: http://bit.ly/paypal-verify-urgent
            
You have 24 hours to confirm your identity or your account will be permanently closed.
            
Thank you,
PayPal Security Team
            """,
            "attachments": ["account_verification.exe"]
        },
        {
            "sender": "notifications@amazon.com",
            "subject": "Your Order Confirmation",
            "content": """
Thank you for your recent purchase. Your order #123456 will be shipped within 2-3 business days.
            
Track your order: https://amazon.com/track/123456
            
Best regards,
Amazon Customer Service
            """,
            "attachments": []
        }
    ]
    
    print("PHISHING EMAIL DETECTION AGENT")
    print("=" * 40)
    
    for i, email in enumerate(test_emails, 1):
        print(f"\nTesting Email #{i}")
        print("-" * 20)
        
        result = detector.analyze_email(
            email['content'],
            email['sender'],
            email['subject'],
            email['attachments']
        )
        
        print(detector.generate_report(result))
        print(f"Quarantine Decision: {'YES' if detector.should_quarantine(result) else 'NO'}")
        print("\n" + "=" * 50)