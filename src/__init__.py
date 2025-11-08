"""
URL Phishing Detection System
A machine learning-based system to detect phishing URLs
"""

__version__ = "1.0.0"
__author__ = "Lakshmy Venkitaraman"

from .feature_extraction import URLFeatureExtractor, extract_features_from_urls
from .prediction import PhishingPredictor, predict_url

__all__ = [
    'URLFeatureExtractor',
    'extract_features_from_urls',
    'PhishingPredictor',
    'predict_url'
]