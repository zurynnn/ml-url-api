import joblib
import pandas as pd
from feature_extractor import extract_features, suspicious_list
from urllib.parse import urlparse
import os
import requests as req

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Load model (RF))
model = joblib.load(os.path.join(BASE_DIR, "rf_model_compressed.pkl"))
# Load feature order
features = joblib.load(os.path.join(BASE_DIR, "features.pkl"))

# URL Normalisation
def normalize_url(url):
    # Add https:// if the URL has no scheme
    if not url.startswith("http"):
        url = "https://" + url
    
    parsed = urlparse(url)
    
    # Split the domain into parts to count segments
    domain_parts = parsed.netloc.split('.')

    # Skip if already has www or has subdomains
    if len(domain_parts) == 2 and not parsed.netloc.startswith("www."):
        url = url.replace(parsed.netloc, "www." + parsed.netloc)

    return url

# URL shorterner domains
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'rb.gy', 'cutt.ly', 'tiny.cc', 'is.gd',
    'buff.ly', 'adf.ly', 'shorte.st', 'link.tl'
}

def unshorten_url(url):
    """Follow redirects to get the final destination URL."""
    parsed = urlparse(url)
    domain = parsed.netloc.replace('www.', '')
    
    if domain not in SHORTENER_DOMAINS:
        return url  # not a shortener, return as-is
    
    try:
        response = req.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        print(f"[Unshortened] {url} → {final_url}")
        return final_url
    except Exception as e:
        print(f"[Unshorten failed] {e}")
        return url  # if it fails, analyse the short URL itself
    
# Whitelist domains
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'x.com', 'github.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'wikipedia.org', 'linkedin.com',
    'paypal.com', 'wattpad.com', 'tngdigital.com.my',
    'translate.google.com', 'maps.google.com', 'booking.com'
}

def get_root_domain(netloc):
    """Extract root domain from netloc. e.g. translate.google.com → google.com"""
    parts = netloc.replace('www.', '').split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])  # last two parts = root domain
    return netloc    

# Predict url:
def predict_url(url):
    # 1 Block dangerous schemes immediately
    dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:']
    if any(url.strip().lower().startswith(scheme) for scheme in dangerous_schemes):
        return "Malicious"
    
    # 2 Basic input validation
    if not url or len(url.strip()) < 4:
        return "Invalid URL"
    
    # 3 Normalize & unshorten
    url = normalize_url(url)
    url = unshorten_url(url)

    parsed = urlparse(url)
    if not parsed.netloc:
        return "Invalid URL"

    # Reject domains with no dot (not a real URL)
    if '.' not in parsed.netloc.replace('www.', ''):
        return "Invalid URL"
    
    # 4 Trusted domain check
    root_domain = get_root_domain(parsed.netloc)
    if root_domain in TRUSTED_DOMAINS:
        return "Benign" 
    
    # 5 Rule-based detection
    # Rule 1: Very long query string
    if len(parsed.query) > 120:
        return "Malicious"
        
    # Rule 2: Many subdomains + suspicious words
    subdomain_count = parsed.netloc.count('.')
    suspicious_count = sum(word in url for word in suspicious_list)
    if subdomain_count >= 4 and suspicious_count >= 1:
        return "Malicious"

    # 6 ML model (only reaches here if not trusted) 
    feature_vector = extract_features(url) # Convert URL → feature vector
    df = pd.DataFrame([feature_vector], columns=features) # Convert to DataFrame 
    prediction = model.predict(df)[0] # Predict ML

    # Convert output
    return "Malicious" if prediction == 1 else "Benign"


# Test
if __name__ == "__main__":
    test_url = "https://paypal-login-secure.com"
    result = predict_url(test_url)

    print("URL:", test_url)
    print("Prediction:", result)