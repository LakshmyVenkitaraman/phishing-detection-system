"""
Unit tests for model training and prediction
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import pandas as pd
import numpy as np
from src.model_training import PhishingDetectionModel
from src.prediction import PhishingPredictor


class TestPhishingDetectionModel:
    """Test cases for model training"""
    
    @pytest.fixture
    def sample_data(self):
        """Create sample dataset for testing"""
        data = {
            'url': [
                'https://www.google.com',
                'https://www.github.com',
                'http://phishing-site.com/login',
                'http://192.168.1.1/phish.php',
                'https://www.amazon.com',
                'http://suspicious-verify.com/account'
            ],
            'label': ['legitimate', 'legitimate', 'phishing', 'phishing', 'legitimate', 'phishing']
        }
        return pd.DataFrame(data)
    
    def test_model_initialization(self):
        """Test model initialization"""
        model = PhishingDetectionModel()
        
        assert model is not None
        assert len(model.models) > 0
        assert 'Random Forest' in model.models
    
    def test_feature_preparation(self, sample_data):
        """Test feature preparation"""
        model = PhishingDetectionModel()
        X, y = model.prepare_features(sample_data)
        
        assert X is not None
        assert y is not None
        assert len(X) == len(y)
        assert len(X) > 0
    
    def test_label_encoding(self, sample_data):
        """Test label encoding"""
        model = PhishingDetectionModel()
        X, y = model.prepare_features(sample_data)
        
        # Check if labels are binary (0 or 1)
        assert all(label in [0, 1] for label in y)
        
        # Check if phishing is encoded as 1
        assert y[2] == 1  # phishing URL
        assert y[0] == 0  # legitimate URL


class TestPhishingPredictor:
    """Test cases for prediction"""
    
    def test_url_prediction_structure(self):
        """Test prediction output structure"""
        # Note: This test requires a trained model
        # Skip if model doesn't exist
        model_path = 'data/models/phishing_model.pkl'
        
        if not os.path.exists(model_path):
            pytest.skip("Model not trained yet")
        
        predictor = PhishingPredictor(model_path)
        result = predictor.predict_url("https://www.google.com")
        
        # Check result structure
        assert 'url' in result
        assert 'prediction' in result
        assert 'confidence' in result
        assert 'features' in result
        
        # Check prediction values
        assert result['prediction'] in ['legitimate', 'phishing']
        assert 0 <= result['confidence'] <= 1
    
    def test_batch_prediction(self):
        """Test batch prediction"""
        model_path = 'data/models/phishing_model.pkl'
        
        if not os.path.exists(model_path):
            pytest.skip("Model not trained yet")
        
        predictor = PhishingPredictor(model_path)
        
        urls = [
            "https://www.google.com",
            "http://phishing-site.com/login"
        ]
        
        results = predictor.predict_batch(urls)
        
        assert len(results) == len(urls)
        assert all('prediction' in r for r in results)
    
    def test_invalid_url_handling(self):
        """Test handling of invalid URLs"""
        model_path = 'data/models/phishing_model.pkl'
        
        if not os.path.exists(model_path):
            pytest.skip("Model not trained yet")
        
        predictor = PhishingPredictor(model_path)
        
        # Test with invalid URL
        result = predictor.predict_url("not_a_valid_url")
        
        # Should handle gracefully
        assert result is not None
        assert 'prediction' in result or 'error' in result


def test_feature_importance():
    """Test feature importance extraction"""
    model_path = 'data/models/phishing_model.pkl'
    
    if not os.path.exists(model_path):
        pytest.skip("Model not trained yet")
    
    predictor = PhishingPredictor(model_path)
    importance = predictor.get_feature_importance()
    
    if importance:
        assert isinstance(importance, dict)
        assert len(importance) > 0


def test_prediction_consistency():
    """Test prediction consistency for same URL"""
    model_path = 'data/models/phishing_model.pkl'
    
    if not os.path.exists(model_path):
        pytest.skip("Model not trained yet")
    
    predictor = PhishingPredictor(model_path)
    url = "https://www.google.com"
    
    # Make multiple predictions
    result1 = predictor.predict_url(url)
    result2 = predictor.predict_url(url)
    
    # Should be consistent
    assert result1['prediction'] == result2['prediction']
    assert abs(result1['confidence'] - result2['confidence']) < 0.01


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, '-v'])