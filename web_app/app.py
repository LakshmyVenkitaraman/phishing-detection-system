"""
Flask web application for URL phishing detection
Provides web interface and REST API
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import sys
import os

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.prediction import PhishingPredictor

app = Flask(__name__)
CORS(app)

# Initialize predictor
try:
    predictor = PhishingPredictor('data/models/phishing_model.pkl')
    model_loaded = True
except Exception as e:
    print(f"Warning: Could not load model - {e}")
    print("Please train the model first by running: python src/model_training.py")
    model_loaded = False


@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')


@app.route('/api/predict', methods=['POST'])
def predict():
    """
    API endpoint for URL prediction
    
    Request JSON:
        {
            "url": "http://example.com"
        }
    
    Response JSON:
        {
            "url": "http://example.com",
            "prediction": "phishing" or "legitimate",
            "confidence": 0.95,
            "risk_score": 0.95,
            "features": {...}
        }
    """
    if not model_loaded:
        return jsonify({
            'error': 'Model not loaded. Please train the model first.',
            'success': False
        }), 500
    
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'No URL provided',
                'success': False
            }), 400
        
        url = data['url']
        
        # Validate URL
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        
        # Make prediction
        result = predictor.predict_url(url)
        result['success'] = True
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@app.route('/api/batch-predict', methods=['POST'])
def batch_predict():
    """
    API endpoint for batch URL prediction
    
    Request JSON:
        {
            "urls": ["http://example1.com", "http://example2.com"]
        }
    
    Response JSON:
        {
            "results": [...],
            "success": true
        }
    """
    if not model_loaded:
        return jsonify({
            'error': 'Model not loaded',
            'success': False
        }), 500
    
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({
                'error': 'No URLs provided',
                'success': False
            }), 400
        
        urls = data['urls']
        
        # Validate URLs
        validated_urls = []
        for url in urls:
            if not url.startswith('http://') and not url.startswith('https://'):
                url = 'http://' + url
            validated_urls.append(url)
        
        # Make predictions
        results = predictor.predict_batch(validated_urls)
        
        return jsonify({
            'results': results,
            'count': len(results),
            'success': True
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@app.route('/api/feature-importance', methods=['GET'])
def feature_importance():
    """Get feature importance from the model"""
    if not model_loaded:
        return jsonify({
            'error': 'Model not loaded',
            'success': False
        }), 500
    
    try:
        importance = predictor.get_feature_importance()
        
        if importance:
            return jsonify({
                'feature_importance': importance,
                'success': True
            })
        else:
            return jsonify({
                'error': 'Feature importance not available for this model',
                'success': False
            }), 400
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model_loaded,
        'version': '1.0.0'
    })


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Endpoint not found',
        'success': False
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'error': 'Internal server error',
        'success': False
    }), 500


if __name__ == '__main__':
    print("="*60)
    print("URL Phishing Detection Web Application")
    print("="*60)
    print(f"Model loaded: {model_loaded}")
    
    if not model_loaded:
        print("\n⚠️  WARNING: Model not loaded!")
        print("Please train the model first:")
        print("  python src/model_training.py")
        print("\nStarting app anyway for testing...")
    
    print("\nStarting Flask server...")
    print("Open your browser to: http://localhost:5000")
    print("="*60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)