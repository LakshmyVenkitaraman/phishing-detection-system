"""
Utility functions for URL phishing detection
"""

import re
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import os


def validate_url(url):
    """
    Validate if string is a valid URL
    
    Args:
        url (str): URL string to validate
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def clean_url(url):
    """
    Clean and normalize URL
    
    Args:
        url (str): URL to clean
        
    Returns:
        str: Cleaned URL
    """
    url = url.strip()
    
    # Add http:// if no protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    return url


def load_dataset(filepath, url_column='url', label_column='label'):
    """
    Load dataset from CSV file
    
    Args:
        filepath (str): Path to CSV file
        url_column (str): Name of URL column
        label_column (str): Name of label column
        
    Returns:
        pd.DataFrame: Loaded dataset
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found: {filepath}")
    
    df = pd.read_csv(filepath)
    
    # Validate required columns
    if url_column not in df.columns or label_column not in df.columns:
        raise ValueError(f"Dataset must contain '{url_column}' and '{label_column}' columns")
    
    return df


def save_dataset(df, filepath):
    """
    Save dataset to CSV file
    
    Args:
        df (pd.DataFrame): Dataset to save
        filepath (str): Output file path
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    df.to_csv(filepath, index=False)
    print(f"Dataset saved to {filepath}")


def get_domain_from_url(url):
    """
    Extract domain from URL
    
    Args:
        url (str): URL string
        
    Returns:
        str: Domain name
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return ""


def is_ip_address(text):
    """
    Check if text is an IP address
    
    Args:
        text (str): Text to check
        
    Returns:
        bool: True if IP address, False otherwise
    """
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return bool(ip_pattern.match(text))


def calculate_entropy(text):
    """
    Calculate Shannon entropy of text
    
    Args:
        text (str): Input text
        
    Returns:
        float: Entropy value
    """
    import math
    from collections import Counter
    
    if not text:
        return 0.0
    
    counts = Counter(text)
    length = len(text)
    
    entropy = -sum((count / length) * math.log2(count / length) 
                  for count in counts.values())
    
    return entropy


def print_model_metrics(y_true, y_pred, model_name="Model"):
    """
    Print classification metrics
    
    Args:
        y_true: True labels
        y_pred: Predicted labels
        model_name (str): Name of the model
    """
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    
    print(f"\n{model_name} Metrics:")
    print(f"{'='*50}")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"{'='*50}")


def create_sample_dataset(output_path='data/raw/phishing_urls.csv', num_samples=100):
    """
    Create a sample dataset for testing
    
    Args:
        output_path (str): Path to save dataset
        num_samples (int): Number of samples to generate
    """
    legitimate_urls = [
        'https://www.google.com',
        'https://www.github.com',
        'https://www.amazon.com',
        'https://www.microsoft.com',
        'https://www.apple.com',
        'https://www.facebook.com',
        'https://www.twitter.com',
        'https://www.linkedin.com',
        'https://www.youtube.com',
        'https://www.wikipedia.org',
        'https://www.reddit.com',
        'https://www.stackoverflow.com',
        'https://www.netflix.com',
        'https://www.spotify.com',
        'https://www.instagram.com'
    ]
    
    phishing_urls = [
        'http://secure-login-verify.com/account',
        'http://paypal-security-alert.com/signin',
        'http://192.168.1.1/phishing.php',
        'http://amazon-account-suspended.com/verify',
        'http://banking-security-update.com/login',
        'http://microsoft-account-locked.com/unlock',
        'http://apple-id-verification.com/confirm',
        'http://secure-bank-login.com/account/verify',
        'http://paypal-confirm-identity.com/update',
        'http://facebook-security-check.com/verify',
        'http://netflix-payment-update.com/billing',
        'http://amazon-prime-renewal.com/payment',
        'http://google-account-recovery.com/verify',
        'http://microsoft-support-team.com/help',
        'http://apple-store-verification.com/confirm'
    ]
    
    # Generate dataset
    urls = []
    labels = []
    
    # Add legitimate URLs
    for _ in range(num_samples // 2):
        url = np.random.choice(legitimate_urls)
        urls.append(url)
        labels.append('legitimate')
    
    # Add phishing URLs
    for _ in range(num_samples // 2):
        url = np.random.choice(phishing_urls)
        urls.append(url)
        labels.append('phishing')
    
    # Create DataFrame
    df = pd.DataFrame({
        'url': urls,
        'label': labels
    })
    
    # Shuffle
    df = df.sample(frac=1).reset_index(drop=True)
    
    # Save
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    
    print(f"Sample dataset created: {output_path}")
    print(f"Total URLs: {len(df)}")
    print(f"Legitimate: {len(df[df['label'] == 'legitimate'])}")
    print(f"Phishing: {len(df[df['label'] == 'phishing'])}")
    
    return df


if __name__ == "__main__":
    # Test utilities
    print("Testing utility functions...")
    
    # Test URL validation
    test_url = "https://www.google.com"
    print(f"\nIs valid URL: {validate_url(test_url)}")
    
    # Test entropy calculation
    print(f"Entropy of 'aaaaa': {calculate_entropy('aaaaa'):.4f}")
    print(f"Entropy of 'abcde': {calculate_entropy('abcde'):.4f}")
    
    # Create sample dataset
    print("\nCreating sample dataset...")
    create_sample_dataset(num_samples=20)