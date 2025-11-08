"""
Feature extraction module for URL phishing detection
Extracts various features from URLs to train ML models
"""

import re
from urllib.parse import urlparse
import tldextract

class URLFeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'update', 'secure', 'banking',
            'confirm', 'signin', 'ebay', 'paypal', 'amazon', 'password',
            'suspended', 'locked', 'security', 'alert'
        ]
    
    def extract_features(self, url):
        """
        Extract all features from a URL
        
        Args:
            url (str): URL to extract features from
            
        Returns:
            dict: Dictionary containing all extracted features
        """
        features = {}
        
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            
            # Basic URL features
            features['url_length'] = len(url)
            features['domain_length'] = len(parsed.netloc)
            features['path_length'] = len(parsed.path)
            
            # Protocol features
            features['is_https'] = 1 if parsed.scheme == 'https' else 0
            
            # Domain features
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_slashes'] = url.count('/')
            features['num_at'] = url.count('@')
            features['num_ampersand'] = url.count('&')
            features['num_equals'] = url.count('=')
            features['num_question'] = url.count('?')
            
            # Check for IP address
            features['has_ip'] = self._has_ip_address(parsed.netloc)
            
            # Subdomain features
            features['num_subdomains'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
            
            # Suspicious patterns
            features['has_suspicious_words'] = self._has_suspicious_words(url.lower())
            features['has_double_slash_redirect'] = 1 if url.count('//') > 1 else 0
            
            # Special characters count
            features['special_char_count'] = self._count_special_chars(url)
            features['digit_count'] = sum(c.isdigit() for c in url)
            features['letter_count'] = sum(c.isalpha() for c in url)
            
            # Domain name features
            features['domain_has_digits'] = sum(c.isdigit() for c in parsed.netloc)
            features['domain_entropy'] = self._calculate_entropy(parsed.netloc)
            
            # Path features
            features['path_depth'] = parsed.path.count('/')
            
            # URL shortening service
            features['is_shortened'] = self._is_shortened_url(ext.domain)
            
            # Port number
            features['has_port'] = 1 if parsed.port else 0
            
            # TLD (top-level domain) features
            features['tld_length'] = len(ext.suffix)
            
            # Random pattern detection
            features['has_random_pattern'] = self._has_random_pattern(parsed.netloc)
            
        except Exception as e:
            print(f"Error extracting features from {url}: {e}")
            return None
        
        return features
    
    def _has_ip_address(self, domain):
        """Check if domain contains IP address"""
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        return 1 if ip_pattern.search(domain) else 0
    
    def _has_suspicious_words(self, url):
        """Check for suspicious keywords in URL"""
        return 1 if any(word in url for word in self.suspicious_keywords) else 0
    
    def _count_special_chars(self, url):
        """Count special characters in URL"""
        special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        return sum(url.count(char) for char in special_chars)
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        import math
        from collections import Counter
        
        if not text:
            return 0
        
        counts = Counter(text)
        length = len(text)
        entropy = -sum((count / length) * math.log2(count / length) 
                      for count in counts.values())
        return entropy
    
    def _is_shortened_url(self, domain):
        """Check if URL is from a URL shortening service"""
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 
                     'is.gd', 'buff.ly', 'adf.ly', 'shorte.st']
        return 1 if domain in shorteners else 0
    
    def _has_random_pattern(self, domain):
        """Detect random character patterns in domain"""
        # Pattern: alternating letters and numbers (e.g., a1b2c3)
        pattern = re.compile(r'[a-z]{1,2}\d{2,}|[0-9]{2,}[a-z]{1,2}', re.IGNORECASE)
        return 1 if pattern.search(domain) else 0


def extract_features_from_urls(urls):
    """
    Extract features from a list of URLs
    
    Args:
        urls (list): List of URLs
        
    Returns:
        list: List of feature dictionaries
    """
    extractor = URLFeatureExtractor()
    features_list = []
    
    for url in urls:
        features = extractor.extract_features(url)
        if features:
            features['url'] = url
            features_list.append(features)
    
    return features_list


if __name__ == "__main__":
    # Test the feature extractor
    test_urls = [
        "https://www.google.com",
        "http://suspicious-login-verify.com/account/update",
        "http://192.168.1.1/phishing.php"
    ]
    
    extractor = URLFeatureExtractor()
    
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extractor.extract_features(url)
        if features:
            for key, value in features.items():
                print(f"  {key}: {value}")
        print("-" * 50)