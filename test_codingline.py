# Quick test — run this in Python terminal
from urllib.parse import urlparse
url = "https://security.microsoft.com"
parsed = urlparse(url)
parts = parsed.netloc.replace('www.', '').split('.')
print(parts)           # ['security', 'microsoft', 'com']
print('.'.join(parts[-2:]))  # microsoft.com ✅