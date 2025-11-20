import re
from urllib.parse import urlparse
SUSPICIOUS_TOKENS = ['login', 'verify', 'update', 'secure', 'account', 'confirm', 'support', 'billing', 'invoice', 'gift', 'free', 'prize']

def extract_features(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    length = len(url)
    num_digits = sum((ch.isdigit() for ch in url))
    has_ip = bool(re.fullmatch('(?:\\d{1,3}\\.){3}\\d{1,3}', host or ''))
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    has_https = parsed.scheme.lower() == 'https'
    num_tokens = sum((tok in url.lower() for tok in SUSPICIOUS_TOKENS))
    tld_len = len(host.split('.')[-1]) if '.' in host else 0
    path_depth = path.count('/')
    query_len = len(query)
    return {'length': length, 'num_digits': num_digits, 'has_ip': int(has_ip), 'num_dots': num_dots, 'num_hyphens': num_hyphens, 'has_https': int(has_https), 'num_suspicious_tokens': num_tokens, 'tld_len': tld_len, 'path_depth': path_depth, 'query_len': query_len}
FEATURE_ORDER = ['length', 'num_digits', 'has_ip', 'num_dots', 'num_hyphens', 'has_https', 'num_suspicious_tokens', 'tld_len', 'path_depth', 'query_len']