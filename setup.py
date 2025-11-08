"""
Setup script for URL Phishing Detection System
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="phishing-detection-system",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A machine learning system to detect phishing URLs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR_USERNAME/phishing-detection-system",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.24.3",
        "pandas>=2.0.3",
        "scikit-learn>=1.3.0",
        "joblib>=1.3.2",
        "tldextract>=3.4.4",
        "urllib3>=2.0.4",
        "Flask>=2.3.3",
        "Flask-CORS>=4.0.0",
        "Werkzeug>=2.3.7",
        "matplotlib>=3.7.2",
        "seaborn>=0.12.2",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "jupyter>=1.0.0",
            "ipykernel>=6.25.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "phishing-detect=src.prediction:main",
            "phishing-train=src.model_training:main",
            "phishing-web=web_app.app:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)