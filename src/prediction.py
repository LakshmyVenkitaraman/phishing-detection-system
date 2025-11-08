"""
Prediction module for URL phishing detection
Load trained model and make predictions on new URLs
"""

import joblib
import numpy as np
import pandas as pd
from src.feature_extraction import URLFeatureExtractor

class PhishingPredictor:
    """Make predictions on URLs using trained model"""
    
    def __init__(self, model_path='data/models/phishing_model.pkl'):
        """
        Initialize predictor with trained model
        
        Args:
            model_path (str): Path to saved model file
        """
        try:
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.extractor = URLFeatureExtractor()
            print("Model loaded successfully!")
        except FileNotFoundError:
            print(f"Error: Model not found at {model_path}")
            print("Please train the model first using model_training.py")
            raise
    
    def predict_url(self, url):
        """
        Predict if a URL is phishing or legitimate
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Prediction results including label, confidence, and features
        """
        # Extract features
        features = self.extractor.extract_features(url)
        
        if not features:
            return {
                'url': url,
                'prediction': 'error',
                'confidence': 0.0,
                'message': 'Could not extract features from URL'
            }
        
        # Convert to DataFrame with correct feature order
        features_df = pd.DataFrame([features])
        
        # Ensure all required features are present
        for feature in self.feature_names:
            if feature not in features_df.columns:
                features_df[feature] = 0
        
        # Select only the features used during training
        features_df = features_df[self.feature_names]
        
        # Scale features
        features_scaled = self.scaler.transform(features_df)
        
        # Make prediction
        prediction = self.model.predict(features_scaled)[0]
        
        # Get probability scores
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(features_scaled)[0]
            confidence = probabilities[prediction]
        else:
            confidence = 1.0  # Some models don't support predict_proba
        
        # Prepare result
        result = {
            'url': url,
            'prediction': 'phishing' if prediction == 1 else 'legitimate',
            'confidence': float(confidence),
            'risk_score': float(confidence) if prediction == 1 else float(1 - confidence),
            'features': features
        }
        
        return result
    
    def predict_batch(self, urls):
        """
        Predict multiple URLs at once
        
        Args:
            urls (list): List of URLs to analyze
            
        Returns:
            list: List of prediction results
        """
        results = []
        
        for url in urls:
            result = self.predict_url(url)
            results.append(result)
        
        return results
    
    def get_feature_importance(self):
        """
        Get feature importance from the model
        
        Returns:
            dict: Feature names and their importance scores
        """
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            feature_importance = dict(zip(self.feature_names, importances))
            # Sort by importance
            feature_importance = dict(sorted(feature_importance.items(), 
                                           key=lambda x: x[1], reverse=True))
            return feature_importance
        else:
            return None


def predict_url(url, model_path='data/models/phishing_model.pkl'):
    """
    Convenience function to predict a single URL
    
    Args:
        url (str): URL to analyze
        model_path (str): Path to model file
        
    Returns:
        dict: Prediction results
    """
    predictor = PhishingPredictor(model_path)
    return predictor.predict_url(url)


def main():
    """Test the predictor with sample URLs"""
    
    # Initialize predictor
    try:
        predictor = PhishingPredictor()
    except FileNotFoundError:
        print("Please train the model first by running: python src/model_training.py")
        return
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "http://secure-login-verify.com/account/update",
        "http://192.168.1.1/phishing.php",
        "https://www.amazon.com",
        "http://paypal-secure-login.com/verify",
        "https://en.wikipedia.org",
        "http://suspicious-banking-update.com/signin"
    ]
    
    print("="*70)
    print("URL Phishing Detection - Predictions")
    print("="*70)
    
    for url in test_urls:
        result = predictor.predict_url(url)
        
        print(f"\nURL: {url}")
        print(f"Prediction: {result['prediction'].upper()}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Risk Score: {result['risk_score']:.2%}")
        
        if result['prediction'] == 'phishing':
            print("⚠️  WARNING: This URL appears to be a phishing attempt!")
        else:
            print("✓ This URL appears to be legitimate")
        
        print("-"*70)
    
    # Show feature importance
    print("\n" + "="*70)
    print("Top 10 Most Important Features")
    print("="*70)
    
    feature_importance = predictor.get_feature_importance()
    if feature_importance:
        for i, (feature, importance) in enumerate(list(feature_importance.items())[:10], 1):
            print(f"{i}. {feature}: {importance:.4f}")


if __name__ == "__main__":
    main()