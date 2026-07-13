import os
import re
import math
import joblib
import numpy as np
import pandas as pd

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "random_forest_model.pkl")

rf_model = None
try:
    if os.path.exists(MODEL_PATH):
        rf_model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"Failed to load ML model: {e}")

suspicious_words = [
    "login", "verify", "update", "secure", "account",
    "bank", "paypal", "signin", "free", "bonus"
]

def shannon_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    return -sum([p * math.log2(p) for p in prob])

def extract_features(url):
    # Lexical features
    url_length = len(url)
    try:
        # Strip scheme for hostname
        clean_url = url.replace("https://", "").replace("http://", "")
        hostname_length = len(clean_url.split('/')[0])
    except:
        hostname_length = 0
        
    num_subdirectories = url.count('/')
    
    # Char features
    num_digits = sum(c.isdigit() for c in url)
    num_special_chars = len(re.findall(r'[^a-zA-Z0-9]', url))
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_underscores = url.count('_')
    num_at = url.count('@')
    num_question = url.count('?')
    num_equal = url.count('=')
    num_percent = url.count('%')
    
    # Token features
    tokens = re.split(r'[./?=&\-_]', str(url))
    valid_tokens = [t for t in tokens if len(t) > 0]
    
    if len(valid_tokens) == 0:
        num_tokens = 0
        avg_token_length = 0
        longest_token_length = 0
    else:
        num_tokens = len(valid_tokens)
        avg_token_length = np.mean([len(t) for t in valid_tokens])
        longest_token_length = max([len(t) for t in valid_tokens])
        
    # Suspicious words
    url_lower = url.lower()
    has_words = {word: int(word in url_lower) for word in suspicious_words}
    
    # Domain features
    has_ip_address = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
    has_https = int("https" in url_lower)
    
    try:
        clean_url = url.replace("https://", "").replace("http://", "")
        hostname = clean_url.split('/')[0]
        tld_length = len(hostname.split('.')[-1]) if '.' in hostname else 0
    except:
        tld_length = 0
        
    url_entropy = shannon_entropy(url)
    
    # Return exactly 29 features in order
    features = [
        url_length, hostname_length, num_subdirectories, num_digits,
        num_special_chars, num_dots, num_hyphens, num_underscores,
        num_at, num_question, num_equal, num_percent, num_tokens,
        avg_token_length, longest_token_length,
        has_words["login"], has_words["verify"], has_words["update"], has_words["secure"], has_words["account"],
        has_words["bank"], has_words["paypal"], has_words["signin"], has_words["free"], has_words["bonus"],
        has_ip_address, has_https, tld_length, url_entropy
    ]
    
    feature_names = [
        'url_length', 'hostname_length', 'num_subdirectories', 'num_digits',
        'num_special_chars', 'num_dots', 'num_hyphens', 'num_underscores',
        'num_at', 'num_question', 'num_equal', 'num_percent', 'num_tokens',
        'avg_token_length', 'longest_token_length', 'has_login', 'has_verify',
        'has_update', 'has_secure', 'has_account', 'has_bank', 'has_paypal',
        'has_signin', 'has_free', 'has_bonus', 'has_ip_address', 'has_https',
        'tld_length', 'url_entropy'
    ]
    
    return pd.DataFrame([features], columns=feature_names)

def analyze_url_ml(url: str):
    if rf_model is None:
        return {"error": "Random Forest ML Model not found."}
        
    try:
        X = extract_features(url)
        prediction = rf_model.predict(X)[0]
        probabilities = rf_model.predict_proba(X)[0]
        
        # Label mapping (based on alphabetical order of LabelEncoder)
        classes = ["benign", "defacement", "malware", "phishing"]
        pred_label = classes[prediction]
        
        confidence = float(np.max(probabilities))
        
        # Format feature dict for display
        features_dict = X.to_dict(orient="records")[0]
        
        return {
            "ml_analysis": {
                "url": url,
                "prediction": pred_label,
                "confidence": round(confidence * 100, 2),
                "features_extracted": features_dict,
                "class_probabilities": {
                    "benign": round(probabilities[0] * 100, 2),
                    "defacement": round(probabilities[1] * 100, 2),
                    "malware": round(probabilities[2] * 100, 2),
                    "phishing": round(probabilities[3] * 100, 2)
                }
            }
        }
    except Exception as e:
        return {"error": f"ML Analysis Failed: {str(e)}"}
