import re
import math
from urllib.parse import urlparse

suspicious_list = [
    # account / login
    'login', 'signin', 'account', 'verify', 'verification',
    'password', 'update', 'confirm', 'secure', 'secured',

    # urgency / threat
    'urgent', 'immediately', 'action', 'required', 'alert',
    'warning', 'blocked', 'suspended', 'expired', 'risk',

    # reward / bait
    'bonus', 'lucky', 'free', 'prize', 'winner', 'gift', 'claim',

    # financial
    'bank', 'banking', 'billing', 'refund', 'payment',

    # auth/security tricks
    'authenticate', 'security', 'validation', 'authorize', 'token',

    # suspicious URL patterns
    'secure-', '-secure', 'login-', 'verify-', 'account-',
    'update-', 'redirect', 'signin-',

    # technical / phishing-specific
    'webscr', 'ebayisapi', 'admin', 'myaccount',
    'securewebsession', 'redirectme', 'recovery',
    'webservis', 'giveaway', 'webspace', 'servico',
    'webnode', 'dispute', 'temporary', 'restore',
    'resolution', '000webhostapp', 'webhostapp'
]

def _entropy(s):
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def extract_features(url):

    url = url.lower()

    return [
        len(url),  # url_length
        url.count('.'),  # num_dots
        1 if url.startswith("https") else 0,  # has_https
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,  # has_ip
        url.count('/'),  # num_subdirs
        url.count('?') + url.count('&'),  # num_params

        sum(word in url for word in suspicious_list),  # suspicious_words

        len(re.findall(r'[-_%@=~]', url)),  # special_char_count

        sum(c.isdigit() for c in url),  # digits_count

        _entropy(url),  # entropy (for FYP demo - improve later)

        len(urlparse(url).netloc),  # domain_length

        urlparse(url).netloc.count('.')  # num_subdomains
    ]
