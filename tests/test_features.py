"""
Unit tests for feature extraction
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from src.feature_extraction import URLFeatureExtractor


class TestURLFeatureExtractor:
    """Test cases for URL feature extraction"""
    
    @pytest.fixture
    def extractor(self):
        """Create feature extractor instance"""
        return URLFeatureExtractor()
    
    def test_legitimate_url(self, extractor):
        """Test feature extraction on legitimate URL"""
        url = "https://www.google.com"
        features = extractor.extract_features(url)
        
        assert features is not None
        assert features['is_https'] == 1
        assert features['has_ip'] == 0
        assert features['has_suspicious_words'] == 0
    
    def test_phishing_url(self, extractor):
        """Test feature extraction on phishing URL"""
        url = "http://secure-login-verify.com/account"
        features = extractor.extract_features(url)
        
        assert features is not None
        assert features['is_https'] == 0
        assert features['has_suspicious_words'] == 1
    
    def test_ip_address_detection(self, extractor):
        """Test IP address detection"""
        url = "http://192.168.1.1/phishing.php"
        features = extractor.extract_features(url)
        
        assert features['has_ip'] == 1
    
    def test_url_length(self, extractor):
        """Test URL length calculation"""
        short_url = "https://google.com"
        long_url = "https://very-long-suspicious-domain-name-here.com/very/long/path/with/many/segments"
        
        features_short = extractor.extract_features(short_url)
        features_long = extractor.extract_features(long_url)
        
        assert features_short['url_length'] < features_long['url_length']
    
    def test_special_characters(self, extractor):
        """Test special character counting"""
        url = "https://example.com?param1=value1&param2=value2"
        features = extractor.extract_features(url)
        
        assert features['special_char_count'] > 0
        assert features['num_equals'] == 2
        assert features['num_ampersand'] == 1
    
    def test_subdomain_count(self, extractor):
        """Test subdomain counting"""
        url_no_subdomain = "https://example.com"
        url_with_subdomain = "https://www.mail.example.com"
        
        features_no = extractor.extract_features(url_no_subdomain)
        features_with = extractor.extract_features(url_with_subdomain)
        
        assert features_with['num_subdomains'] > features_no['num_subdomains']
    
    def test_invalid_url(self, extractor):
        """Test handling of invalid URL"""
        invalid_url = "not_a_valid_url"
        features = extractor.extract_features(invalid_url)
        
        # Should handle gracefully and return None or empty features
        assert features is None or isinstance(features, dict)
    
    def test_https_detection(self, extractor):
        """Test HTTPS protocol detection"""
        https_url = "https://secure-site.com"
        http_url = "http://insecure-site.com"
        
        features_https = extractor.extract_features(https_url)
        features_http = extractor.extract_features(http_url)
        
        assert features_https['is_https'] == 1
        assert features_http['is_https'] == 0


def test_suspicious_keywords():
    """Test suspicious keyword detection"""
    extractor = URLFeatureExtractor()
    
    # URLs with suspicious keywords
    suspicious_urls = [
        "http://paypal-login.com",
        "http://verify-account.com",
        "http://secure-banking.com"
    ]
    
    for url in suspicious_urls:
        features = extractor.extract_features(url)
        assert features['has_suspicious_words'] == 1


def test_entropy_calculation():
    """Test entropy calculation"""
    extractor = URLFeatureExtractor()
    
    # Low entropy (repetitive)
    low_entropy_url = "http://aaaaaaa.com"
    # High entropy (random)
    high_entropy_url = "http://ab3cd9ef2gh.com"
    
    features_low = extractor.extract_features(low_entropy_url)
    features_high = extractor.extract_features(high_entropy_url)
    
    # High entropy domain should have higher entropy value
    assert features_high['domain_entropy'] > features_low['domain_entropy']


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, '-v'])