import joblib
import pandas as pd
from feature_extractor import extract_features, suspicious_list
from urllib.parse import urlparse
import os
import requests as req
import unicodedata  # NEW
import re
import ipaddress
import logging

logging.basicConfig(level=logging.INFO)

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
    domain_parts = parsed.netloc.split('.') # Split the domain into parts to count segments

    # Skip adding www. for known shortener domains
    root = '.'.join(parsed.netloc.split('.')[-2:])
    if root in SHORTENER_DOMAINS_NO_WWW:
        return url
    
    # Skip if already has www or has subdomains
    if len(domain_parts) == 2 and not parsed.netloc.startswith("www."):
        url = url.replace(parsed.netloc, "www." + parsed.netloc)

    return url

# URL shorterner domains
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'rb.gy', 'cutt.ly', 'tiny.cc', 'is.gd',
    'buff.ly', 'adf.ly', 'shorte.st', 'link.tl', 'qrco.de',
    'short.gy', 'cli.gs', 'tr.im', 'v.gd', 'tinyurl.com',
    'shorturl.at', 'rb.gy', '9qr.de', 'qri.us', 'qrs.ly',
    'qr.ae', 'chl.li', 'soo.gd', '2.gp', 'gg.gg'
}

SHORTENER_DOMAINS_NO_WWW = {
    'bit.ly', 't.co', 'rb.gy', 'qrco.de', 'cutt.ly', 
    'tiny.cc', 'is.gd', 'ow.ly', 'v.gd', 'tr.im'
}

# Whitelist domains
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'x.com', 'github.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'wikipedia.org', 'linkedin.com',
    'paypal.com', 'wattpad.com', 'tngdigital.com.my',
    'translate.google.com', 'maps.google.com', 'booking.com',
    'jobstreet.com', 'indeed.com', 'linkedin.com'
}

# Suspicious TLDs (for scoring system)
SUSPICIOUS_TLDS = {
    '.online', '.click', '.link', '.xyz', '.top', '.club',
    '.live', '.site', '.website', '.space', '.fun', '.pw'
}

# High risk TLDs 
HIGH_RISK_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.pw'}

# Benign file extensions 
BENIGN_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3', '.zip'
}

#Homograph 
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

def is_safe_url(url):
    parsed = urlparse(url)

    if not parsed.hostname:
        return False
    
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        return not (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local
        )
    except ValueError:
        pass  # iF hostname, not an IP - OK

    if parsed.hostname.startswith("-") or parsed.hostname.endswith("-"):
        return False
    
    return True

def unshorten_url(url):
    """Follow redirects to get the final destination URL."""
    parsed = urlparse(url)
    domain = parsed.netloc.replace('www.', '')
    
    if domain not in SHORTENER_DOMAINS:
        return url  # not a shortener, return as-is
    
    if not is_safe_url(url):
        return url
    
    try:
        response = req.head(url, allow_redirects=True, timeout=5)
        final_url = response.url

        if not is_safe_url(final_url):
            return url

        print(f"[Unshortened] {url} → {final_url}")
        return final_url
            
    except Exception as e:
        logging.warning(f"Unshorten failed: {e}")
        return url  # if it fails, analyse the short URL itself
    
def get_root_domain(netloc):
    """Extract root domain from netloc. e.g. translate.google.com → google.com"""
    parts = netloc.replace('www.', '').split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])  # last two parts = root domain
    return netloc

# ========== SCORING SYSTEM ==========
def calculate_malicious_score(url, parsed):
    """Calculate malicious score 0-100 based on multiple signals - STRONGER VERSION"""
    score = 0
    reasons = []
    
    # SIGNAL 1: TLD risk (0-45 points) - INCREASED
    tld = '.' + parsed.netloc.split('.')[-1]
    
    if tld in HIGH_RISK_TLDS:
        score += 45  # Was 35
        reasons.append(f"High-risk TLD: {tld}")
    elif tld in SUSPICIOUS_TLDS:
        score += 30  # Was 20
        reasons.append(f"Suspicious TLD: {tld}")
    
    # SIGNAL 2: Suspicious path keywords (0-35 points)
    scam_path_keywords = ['verify', 'secure', 'update', 'confirm', 'login', 'signin', 
                          'account', 'alert', 'warning', 'notification', 'claim', 'win',
                          'semak', 'bantuan', 'kemaskini', 'subsidi', 'banci', 
                          'pengesahan', 'permohonan', 'jawatan', 'kosong', 'terkini']  
    
    path_lower = parsed.path.lower()
    full_url_lower = url.lower()
    
    # Check both path and full URL for keywords
    scam_count = sum(1 for keyword in scam_path_keywords 
                    if keyword in path_lower or keyword in full_url_lower)
    
    if scam_count >= 2:
        score += min(35, scam_count * 10)  
        reasons.append(f"Suspicious keywords: {scam_count} matches")
    elif scam_count == 1:
        score += 15
        reasons.append(f"Suspicious keyword found")
    
    # SIGNAL 3: URL length (0-20 points)
    if len(url) > 120:
        score += 15  # Was 10
        reasons.append("Very long URL > 120 chars")
    elif len(url) > 90:  # Lowered threshold
        score += 8
        reasons.append("Long URL > 90 chars")
    
    # SIGNAL 4: Deep path nesting (0-15 points)
    path_depth = parsed.path.count('/')
    if path_depth > 5:
        score += 15  # Was 10
        reasons.append(f"Deep path nesting: {path_depth}")
    elif path_depth > 3:
        score += 8  # Was 5
    
    # SIGNAL 5: Many subdomains (0-20 points)
    subdomain_count = parsed.netloc.count('.') - 1
    if subdomain_count >= 3:
        score += min(20, subdomain_count * 7) 
        reasons.append(f"Many subdomains: {subdomain_count}")
    elif subdomain_count == 2:
        score += 5
    
    # SIGNAL 6: Query parameters (0-15 points)
    if parsed.query:
        if len(parsed.query) > 80:
            score += 10  # Was 8
            reasons.append("Long query string")
        if '=' in parsed.query and parsed.query.count('&') > 2:  # Was 3
            score += 8  # Was 5
            reasons.append("Multiple query parameters")
    
    # SIGNAL 7: Non-standard port (0-10 points)
    if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
        score += 10  # Was 5
        reasons.append(f"Non-standard port: {parsed.port}")
    
    # SIGNAL 8: Suspicious domain patterns (NEW)
    netloc = parsed.netloc.lower()
    suspicious_domain_patterns = ['-secure', '-login', '-verify', '-update', 
                                   'secure-', 'login-', 'verify-', 'account-']
    for pattern in suspicious_domain_patterns:
        if pattern in netloc:
            score += 12
            reasons.append(f"Suspicious domain pattern: {pattern}")
            break
    
    # SIGNAL 9: Numbers in domain (phishing indicator)
    if any(char.isdigit() for char in netloc.split('.')[0]):  # Check subdomain part
        score += 8
        reasons.append("Domain contains numbers")
    
    return score, reasons

def is_likely_legitimate_pdf(parsed):
    """Check if PDF URL appears to be from a legitimate business"""
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # Country TLDs often indicate legitimate businesses
    country_tlds = {'.de', '.uk', '.fr', '.jp', '.au', '.ca', '.my', '.sg', '.nz', '.ch'}
    has_country_tld = any(domain.endswith(tld) for tld in country_tlds)
    
    # Common legitimate business domain patterns
    legitimate_domain_patterns = [
        'restaurant', 'menu', 'cafe', 'hotel', 'travel', 'tourism',
        'brochure', 'catalog', 'product', 'service', 'company',
        'download', 'files', 'docs', 'document', 'pdf', 'assets',
        'static', 'media', 'content', 'uploads', 'wp-content'
    ]
    
    # Check domain/path for legitimate indicators
    has_legitimate_pattern = any(
        pattern in domain or pattern in path 
        for pattern in legitimate_domain_patterns
    )
    
    # Suspicious patterns that override legitimacy
    suspicious_patterns = ['login', 'verify', 'secure', 'update', 'confirm', 
                          'account', 'alert', 'password', 'credential', 'signin']
    has_suspicious_pattern = any(pattern in domain or pattern in path 
                                  for pattern in suspicious_patterns)
    
    # Decision logic
    if has_suspicious_pattern:
        return False  # Even PDFs can be malicious if asking for credentials
    
    if has_country_tld and has_legitimate_pattern:
        return True
    
    # Domain with real business name (e.g., olddubliner.de)
    domain_name = domain.split('.')[0]
    if has_country_tld and len(domain_name) > 3 and domain_name.isalpha():
        return True
    
    return False

def detect_fake_ticker_pattern(url, content=None):
    """Detect fake registration tickers without fetching if no content"""
    # Pattern-based detection from URL/path
    ticker_indicators = [
        'pendaftaran', 'terkini', 'berjaya', 'mendaftar',
        'successfully', 'registered', 'just joined', 'just signed'
    ]
    
    url_lower = url.lower()
    indicator_count = sum(1 for ind in ticker_indicators if ind in url_lower)
    
    if indicator_count >= 2:
        return True
    
    # If we have content, do deeper check
    if content:
        patterns = [
            r'\w+\s+(bin|binti)\s+\w+\s+Berjaya',
            r'✅\s*Berjaya\s*Mendaftar',
            r'Pendaftaran\s+Terkini',
            r'just\s+joined.*✅',
            r'Berjaya.*✅'
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
    
    return False    

# Predict url:
def predict_url(url):
    # 1 Block dangerous schemes immediately
    dangerous_schemes = ['javascript:', 'data:', 'vbscript:', 'file:']
    if any(url.strip().lower().startswith(scheme) for scheme in dangerous_schemes):
        return {"result": "Malicious", "final_url": url}

    # 2 Basic input validation
    if len(url.strip()) > 2048:
        return {"result": "Invalid URL", "final_url": url}

    # 3 Normalize & unshorten
    url = normalize_url(url)
    final_url  = unshorten_url(url)

    parsed = urlparse(url)
    if not parsed.netloc:
        return {"result": "Invalid URL", "final_url": final_url}

    # Reject domains with no dot (not a real URL)
    if '.' not in parsed.netloc.replace('www.', ''):
        return {"result": "Invalid URL", "final_url": final_url}
    
    # 4 Homograph detection
    homograph_result = check_homograph_attack(url)
    if homograph_result['is_attack']:
        return {"result": "Malicious", "final_url": final_url}
    
    # 5 Trusted domain check
    root_domain = get_root_domain(parsed.netloc)
    if root_domain in TRUSTED_DOMAINS:
        return {"result": "Benign", "final_url": final_url}
    
   # 6. PDF special handling - LESS AGGRESSIVE
    if parsed.path.lower().endswith(tuple(BENIGN_EXTENSIONS)):
        # Check if this is likely a legitimate business PDF
        if is_likely_legitimate_pdf(parsed):
            return {"result": "Benign", "final_url": final_url}
        
        # For other PDFs, only mark malicious if ML is very confident
        feature_vector = extract_features(final_url)
        df = pd.DataFrame([feature_vector], columns=features)
        prediction = model.predict(df)[0]
        proba = model.predict_proba(df)[0]
        
        # Only return malicious if ML is > 80% confident
        if prediction == 1 and proba[1] > 0.80:
            return {"result": "Malicious", "final_url": final_url}
        return {"result": "Benign", "final_url": final_url} # Default to benign for PDFs
    
    # 7. Calculate malicious score for non-PDF URLs
    malicious_score, reasons = calculate_malicious_score(final_url, parsed)
    
    # 8. Fake ticker detection (for job scams)
    if detect_fake_ticker_pattern(final_url):
        malicious_score += 25
        reasons.append("Fake registration ticker pattern detected")
    
    # 9. Decision based on score
    if malicious_score >= 30:
        return {"result": "Malicious", "final_url": final_url}
    
    # 10. For moderate scores (10-29), use ML with lower threshold
    if 10 <= malicious_score < 30:  # Was 15-39
        feature_vector = extract_features(final_url)
        df = pd.DataFrame([feature_vector], columns=features)
        prediction = model.predict(df)[0]
        proba = model.predict_proba(df)[0]
                
        # ML needs higher confidence when score is moderate
        if prediction == 1 and proba[1] > 0.60:
            return {"result": "Malicious", "final_url": final_url}
        return {"result": "Benign", "final_url": final_url}
    
    # 11 ML model (For low scores (0-9)) 
    feature_vector = extract_features(final_url) # Convert URL → feature vector
    df = pd.DataFrame([feature_vector], columns=features) # Convert to DataFrame 
    prediction = model.predict(df)[0] # Predict ML
    proba = model.predict_proba(df)[0]

    result = "Malicious" if prediction == 1 else "Benign" # Convert output
    return {"result": result, "final_url": final_url}

# Test
if __name__ == "__main__":
    print("\n===== URL PREDICTION TEST =====\n")
    
    test_urls = [
        # Benign
        "https://www.google.com",
        "https://github.com/",
        "https://www.paypal.com/my/home",
        "http://www.olddubliner.de/Drinks/ODHH_DrinksMenu.pdf",  # Should be Benign
        "https://www.jobstreet.com.my/jobs",  # Real job site
        
        # Malicious
        "https://paypal-login-secure.com",
        "https://jawatan-kosong-terkini.semak-now.online/1/",  # Should be Malicious
        "https://bantuan-kerajaan.online/verify",
        "https://semak-brim.xyz",
        "https://secure-update-account-verify.com",
        
        # Homograph
        "https://www.paypa1.com",
        "https://www.g00gle.com",
        "https://www.arnazon.com",
    ]
    
    for url in test_urls:
        result = predict_url(url)
        print(f"{url[:70]} → {result}")
        print("-" * 80)