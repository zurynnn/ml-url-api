import joblib
import pandas as pd
from feature_extractor import extract_features, suspicious_list
from urllib.parse import urlparse
import os
import requests as req
import unicodedata  # NEW

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

# Whitelist domains
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'x.com', 'github.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'wikipedia.org', 'linkedin.com',
    'paypal.com', 'wattpad.com', 'tngdigital.com.my',
    'translate.google.com', 'maps.google.com', 'booking.com'
}

#Homograph --- NEW
def check_homograph_attack(url):
    """
    Detect homograph/Unicode spoofing attacks.
    Returns {'is_attack': bool, 'reason': str}
    """
    
    # Extract domain from URL
    parsed = urlparse(url)
    domain = parsed.netloc.replace('www.', '')
    
    if not domain:
        return {'is_attack': False, 'reason': None}
    
    # ===== CHECK 1: Mixed Script Detection =====
    # Cyrillic characters that look like Latin
    cyrillic_chars = []
    latin_chars = []
    
    for char in domain:
        try:
            char_name = unicodedata.name(char)
            if 'CYRILLIC' in char_name:
                cyrillic_chars.append(char)
            elif 'GREEK' in char_name:        # ← ADD THIS
                cyrillic_chars.append(char)
            elif 'LATIN' in char_name:
                latin_chars.append(char)
        except (ValueError, TypeError):
            pass
    
    # If domain contains BOTH Cyrillic and Latin characters
    if cyrillic_chars and latin_chars:
        return {
            'is_attack': True,
            'reason': f'Mixed scripts: Cyrillic ({cyrillic_chars}) and Latin characters'
        }
    
    # ===== CHECK 2: Known Lookalike Characters =====
    # Maps Cyrillic → Latin equivalent
    lookalikes = {
        'а': 'a',   # Cyrillic a
        'е': 'e',   # Cyrillic e  
        'о': 'o',   # Cyrillic o
        'р': 'p',   # Cyrillic p
        'с': 'c',   # Cyrillic c
        'у': 'y',   # Cyrillic u
        'х': 'x',   # Cyrillic x
        'к': 'k',   # Cyrillic k
        'м': 'm',   # Cyrillic m
        'н': 'h',   # Cyrillic n
        'в': 'b',   # Cyrillic v
        'т': 't',   # Cyrillic t
        'ө': 'o',
        'ғ': 'f',

        # Greek lookalikes 
        'ο': 'o',   # Greek omicron
        'α': 'a',   # Greek alpha
        'ν': 'v',   # Greek nu
        'κ': 'k',   # Greek kappa
        'ρ': 'p',   # Greek rho
        'ε': 'e',   # Greek epsilon
    }
    
    # Check if domain contains lookalike characters
    for cyrillic_char, latin_char in lookalikes.items():
        if cyrillic_char in domain:
            # Create a "normalized" version
            normalized = domain.replace(cyrillic_char, latin_char)
            
            # Check against trusted domains
            for trusted in TRUSTED_DOMAINS:
                if normalized == trusted or normalized.endswith('.' + trusted):
                    return {
                        'is_attack': True,
                        'reason': f'Lookalike attack: "{domain}" pretends to be "{trusted}" (uses Cyrillic {cyrillic_char} instead of {latin_char})'
                    }
    
    # ===== CHECK 3: Digit Substitution (g00gle → google) =====
    # Only check ASCII domains
    if domain.isascii(): 
        def _normalize_digits(d):
            """Try all digit substitution combinations."""
            # Check for digit substitutions    
            digit_map = {
                '0': 'o',
                '3': 'e',
                '4': 'a',
                '5': 's',
                '7': 't',
                '8': 'b',
                '@': 'a',
                '$': 's'
            }
            # First pass — basic substitution
            normalized = d
            for digit, letter in digit_map.items():
                normalized = normalized.replace(digit, letter)
            
            results = set()
            results.add(normalized)
            # Handle '1' separately — try both 'i' and 'l'
            results.add(normalized.replace('1', 'i'))
            results.add(normalized.replace('1', 'l'))
            return results

        # If normalization changed the domain, check against trusted domains
        normalized_versions = _normalize_digits(domain)
        for normalized in normalized_versions: 
            if normalized != domain: # only if something changed
                for trusted in TRUSTED_DOMAINS:
                    if normalized == trusted or normalized.endswith('.' + trusted):
                        return {
                            'is_attack': True,
                            'reason': f'Digit substitution: "{domain}" looks like "{trusted}"'
                        }
        
    # ===== CHECK 4: Character Substitution (rn → m) =====
    if 'rn' in domain:
        normalized = domain.replace('rn', 'm')
        for trusted in TRUSTED_DOMAINS:
            if normalized == trusted or normalized.endswith('.' + trusted):
                return {
                    'is_attack': True,
                    'reason': f'Character substitution: "{domain}" looks like "{trusted}" (rn → m)'
                }
    
    # ===== CHECK 5: Double Character Substitution (vv → w) =====
    if 'vv' in domain:
        normalized = domain.replace('vv', 'w')
        for trusted in TRUSTED_DOMAINS:
            if normalized == trusted or normalized.endswith('.' + trusted):
                return {
                    'is_attack': True,
                    'reason': f'Character substitution: "{domain}" looks like "{trusted}" (vv → w)'
                }
    
    return {'is_attack': False, 'reason': None}
#//

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
    
    # ========== HOMOGRAPH DETECTION (NEW) ==========
    homograph_result = check_homograph_attack(url)
    if homograph_result['is_attack']:
        print(f"[SECURITY] Homograph detected: {homograph_result['reason']}")
        return "Malicious"
    
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
    test_urls = [
        "https://paypal-login-secure.com",
        "https://google.com",                    # Should be Benign
        "https://gооgle.com",                   # Cyrillic 'o' - should be Malicious
        "https://аррӏе.com",                    # Cyrillic apple - should be Malicious
        "https://paypa1.com",                    # Digit substitution - should be Malicious
        "https://rnicrosoft.com",                # rn → m - should be Malicious
    ]

    for url in test_urls:
        result = predict_url(url)
        print("Prediction:", result)