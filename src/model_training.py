"""
Model training module for URL phishing detection
Trains various ML models and saves the best one
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                            f1_score, classification_report, confusion_matrix)
import joblib
import os
from src.feature_extraction import URLFeatureExtractor, extract_features_from_urls

class PhishingDetectionModel:
    """Train and evaluate phishing detection models"""
    
    def __init__(self):
        self.models = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'SVM': SVC(kernel='rbf', probability=True, random_state=42),
            'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
            'Decision Tree': DecisionTreeClassifier(random_state=42)
        }
        self.best_model = None
        self.scaler = StandardScaler()
        self.feature_names = None
    
    def load_data(self, filepath):
        """
        Load dataset from CSV file
        Expected columns: url, label (phishing=1, legitimate=0)
        """
        print("Loading dataset...")
        df = pd.read_csv(filepath)
        print(f"Dataset loaded: {len(df)} URLs")
        return df
    
    def prepare_features(self, df):
        """Extract features from URLs and prepare for training"""
        print("Extracting features from URLs...")
        
        features_list = []
        labels = []
        
        for idx, row in df.iterrows():
            if idx % 1000 == 0:
                print(f"Processed {idx}/{len(df)} URLs")
            
            extractor = URLFeatureExtractor()
            features = extractor.extract_features(row['url'])
            
            if features:
                features_list.append(features)
                # Convert label to binary (phishing=1, legitimate=0)
                label = 1 if row['label'].lower() in ['phishing', 'bad', '1'] else 0
                labels.append(label)
        
        # Convert to DataFrame
        features_df = pd.DataFrame(features_list)
        
        # Store feature names
        self.feature_names = list(features_df.columns)
        
        print(f"Feature extraction complete. Total features: {len(self.feature_names)}")
        
        return features_df, np.array(labels)
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Train multiple models and compare performance"""
        print("\n" + "="*60)
        print("Training and Evaluating Models")
        print("="*60)
        
        results = {}
        
        for name, model in self.models.items():
            print(f"\nTraining {name}...")
            
            # Train model
            model.fit(X_train, y_train)
            
            # Predictions
            y_pred = model.predict(X_test)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1
            }
            
            print(f"Accuracy:  {accuracy:.4f}")
            print(f"Precision: {precision:.4f}")
            print(f"Recall:    {recall:.4f}")
            print(f"F1 Score:  {f1:.4f}")
            
            # Cross-validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=5)
            print(f"Cross-validation Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        # Find best model
        best_model_name = max(results, key=lambda x: results[x]['f1_score'])
        self.best_model = results[best_model_name]['model']
        
        print("\n" + "="*60)
        print(f"Best Model: {best_model_name}")
        print(f"F1 Score: {results[best_model_name]['f1_score']:.4f}")
        print("="*60)
        
        return results, best_model_name
    
    def save_model(self, model_path='data/models/phishing_model.pkl'):
        """Save the trained model and scaler"""
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        model_data = {
            'model': self.best_model,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        
        joblib.dump(model_data, model_path)
        print(f"\nModel saved to {model_path}")
    
    def generate_classification_report(self, X_test, y_test):
        """Generate detailed classification report"""
        y_pred = self.best_model.predict(X_test)
        
        print("\nClassification Report:")
        print("="*60)
        print(classification_report(y_test, y_pred, 
                                   target_names=['Legitimate', 'Phishing']))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        return classification_report(y_test, y_pred), cm


def main():
    """Main training pipeline"""
    
    # Initialize model trainer
    trainer = PhishingDetectionModel()
    
    # Load data (you need to provide your dataset)
    # Dataset should have columns: 'url', 'label'
    data_path = 'data/raw/phishing_urls.csv'
    
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at {data_path}")
        print("Please download a phishing URL dataset and place it in data/raw/")
        print("\nCreating sample dataset for demonstration...")
        
        # Create sample data
        sample_data = {
            'url': [
                'https://www.google.com',
                'https://www.github.com',
                'http://suspicious-login.com/verify',
                'http://192.168.1.1/phishing.php',
                'https://www.amazon.com',
                'http://secure-paypal-login.com/account'
            ],
            'label': ['legitimate', 'legitimate', 'phishing', 'phishing', 'legitimate', 'phishing']
        }
        
        df = pd.DataFrame(sample_data)
        os.makedirs('data/raw', exist_ok=True)
        df.to_csv(data_path, index=False)
        print(f"Sample dataset created at {data_path}")
    
    # Load dataset
    df = trainer.load_data(data_path)
    
    # Extract features
    X, y = trainer.prepare_features(df)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    X_train_scaled = trainer.scaler.fit_transform(X_train)
    X_test_scaled = trainer.scaler.transform(X_test)
    
    # Train models
    results, best_model_name = trainer.train_models(
        X_train_scaled, X_test_scaled, y_train, y_test
    )
    
    # Generate detailed report
    trainer.generate_classification_report(X_test_scaled, y_test)
    
    # Save model
    trainer.save_model()
    
    print("\nTraining complete!")
    print("You can now use the model for predictions with prediction.py")


if __name__ == "__main__":
    main()