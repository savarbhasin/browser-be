import re
import ssl
import socket
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import dns.resolver
import whois
import difflib
from math import log2

class DomainAgeChecker:

    def __init__(self, suspicious_days: int=90):
        self.suspicious_days = suspicious_days

    async def check(self, url: str) -> Dict[str, Any]:
        try:
            domain = urlparse(url).hostname
            if not domain:
                return {'error': 'Invalid domain', 'suspicious': False}
            if not isinstance(domain, str) or len(domain) == 0:
                return {'error': 'Invalid domain format', 'suspicious': False}
            loop = asyncio.get_event_loop()
            try:
                w = await loop.run_in_executor(None, whois.whois, domain)
            except (socket.gaierror, ValueError) as e:
                return {'error': f'DNS resolution failed: {str(e)}', 'suspicious': False, 'reason': 'WHOIS lookup failed (DNS/network issue)'}
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                if creation_date.tzinfo:
                    creation_date = creation_date.replace(tzinfo=None)
                now = datetime.now()
                age_days = (now - creation_date).days
                is_new = age_days < self.suspicious_days
                return {'age_days': age_days, 'is_newly_registered': is_new, 'creation_date': creation_date.isoformat(), 'registrar': getattr(w, 'registrar', 'Unknown'), 'suspicious': is_new, 'reason': f'Domain is only {age_days} days old' if is_new else None}
            else:
                return {'error': 'Could not determine creation date', 'suspicious': True, 'reason': 'WHOIS data unavailable'}
        except Exception as e:
            return {'error': str(e), 'suspicious': False, 'reason': 'WHOIS lookup failed'}

class SSLCertificateChecker:

    def __init__(self, timeout: int=5):
        self.timeout = timeout

    async def check(self, url: str) -> Dict[str, Any]:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return {'error': 'Invalid hostname', 'suspicious': False, 'valid': False}
            if parsed.scheme.lower() != 'https':
                return {'valid': False, 'reason': 'Not using HTTPS', 'suspicious': True}
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(None, self._get_certificate, hostname)
            return cert_info
        except ValueError as e:
            return {'valid': False, 'error': str(e), 'suspicious': False, 'reason': 'Could not verify SSL certificate (DNS/network issue)'}
        except Exception as e:
            return {'valid': False, 'error': str(e), 'suspicious': False, 'reason': 'SSL certificate check failed'}

    def _get_certificate(self, hostname: str) -> Dict[str, Any]:
        if not hostname or not isinstance(hostname, str):
            raise ValueError(f'Invalid hostname: {hostname}')
        if any((ord(c) > 127 for c in hostname)):
            raise ValueError(f'Hostname contains invalid characters: {hostname}')
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after_str = cert['notAfter']
                    not_before_str = cert['notBefore']
                    try:
                        not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    except ValueError:
                        not_after = datetime.strptime(not_after_str.split(' GMT')[0], '%b %d %H:%M:%S %Y')
                    try:
                        not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                    except ValueError:
                        not_before = datetime.strptime(not_before_str.split(' GMT')[0], '%b %d %H:%M:%S %Y')
                    now = datetime.now()
                    if not_after.tzinfo:
                        not_after = not_after.replace(tzinfo=None)
                    if not_before.tzinfo:
                        not_before = not_before.replace(tzinfo=None)
                    days_until_expiry = (not_after - now).days
                    cert_age_days = (now - not_before).days
                    issuer = dict((x[0] for x in cert['issuer']))
                    subject = dict((x[0] for x in cert['subject']))
                    is_self_signed = issuer.get('organizationName') == subject.get('organizationName')
                    issuer_org = issuer.get('organizationName', '').lower()
                    suspicious = False
                    reasons = []
                    if is_self_signed:
                        suspicious = True
                        reasons.append('Self-signed certificate')
                    if days_until_expiry < 30:
                        suspicious = True
                        reasons.append(f'Certificate expires in {days_until_expiry} days')
                    if cert_age_days < 7:
                        suspicious = True
                        reasons.append(f'Certificate is only {cert_age_days} days old')
                    return {'valid': True, 'days_until_expiry': days_until_expiry, 'cert_age_days': cert_age_days, 'issuer': issuer.get('organizationName', 'Unknown'), 'is_self_signed': is_self_signed, 'subject': subject.get('commonName', 'Unknown'), 'suspicious': suspicious, 'reason': '; '.join(reasons) if reasons else None}
        except socket.gaierror as e:
            raise ValueError(f'DNS resolution failed for {hostname}: {str(e)}')
        except socket.timeout:
            raise ValueError(f'Connection timeout for {hostname}')
        except socket.error as e:
            raise ValueError(f'Socket error for {hostname}: {str(e)}')
        except Exception as e:
            raise ValueError(f'SSL certificate check failed for {hostname}: {str(e)}')

class DNSChecker:

    def __init__(self, timeout: int=5):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def check(self, url: str) -> Dict[str, Any]:
        try:
            domain = urlparse(url).hostname
            if not domain:
                return {'error': 'Invalid domain', 'suspicious': False}
            if not isinstance(domain, str) or len(domain) == 0:
                return {'error': 'Invalid domain format', 'suspicious': False}
            loop = asyncio.get_event_loop()
            has_mx = await loop.run_in_executor(None, self._check_mx, domain)
            has_a = await loop.run_in_executor(None, self._check_a, domain)
            has_aaaa = await loop.run_in_executor(None, self._check_aaaa, domain)
            nameservers = await loop.run_in_executor(None, self._get_nameservers, domain)
            suspicious = False
            reasons = []
            if not has_a and (not has_aaaa):
                suspicious = True
                reasons.append('No A or AAAA records found')
            if len(nameservers) == 0 and suspicious:
                reasons.append('No nameservers found')
            return {'has_mx_records': has_mx, 'has_a_records': has_a, 'has_aaaa_records': has_aaaa, 'nameserver_count': len(nameservers), 'nameservers': nameservers[:3], 'suspicious': suspicious, 'reason': '; '.join(reasons) if reasons else None}
        except (socket.gaierror, ValueError) as e:
            return {'error': f'DNS resolution failed: {str(e)}', 'suspicious': False, 'reason': 'DNS lookup failed (network/DNS issue)'}
        except Exception as e:
            return {'error': str(e), 'suspicious': False, 'reason': 'DNS lookup failed'}

    def _check_mx(self, domain: str) -> bool:
        try:
            if not domain or not isinstance(domain, str):
                return False
            mx_records = self.resolver.resolve(domain, 'MX')
            return len(list(mx_records)) > 0
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, socket.gaierror, ValueError):
            return False
        except Exception:
            return False

    def _check_a(self, domain: str) -> bool:
        try:
            if not domain or not isinstance(domain, str):
                return False
            a_records = self.resolver.resolve(domain, 'A')
            return len(list(a_records)) > 0
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, socket.gaierror, ValueError):
            return False
        except Exception:
            return False

    def _check_aaaa(self, domain: str) -> bool:
        try:
            if not domain or not isinstance(domain, str):
                return False
            aaaa_records = self.resolver.resolve(domain, 'AAAA')
            return len(list(aaaa_records)) > 0
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, socket.gaierror, ValueError):
            return False
        except Exception:
            return False

    def _get_nameservers(self, domain: str) -> List[str]:
        try:
            if not domain or not isinstance(domain, str):
                return []
            ns_records = self.resolver.resolve(domain, 'NS')
            return [str(ns) for ns in ns_records]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, socket.gaierror, ValueError):
            return []
        except Exception:
            return []

class TyposquattingChecker:

    def __init__(self, brands_file: Optional[str]=None):
        self.known_brands = self._load_brands(brands_file)

    def _load_brands(self, brands_file: Optional[str]) -> List[str]:
        if brands_file:
            try:
                with open(brands_file, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception:
                pass
        return ['google.com', 'facebook.com', 'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com', 'netflix.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'ebay.com', 'yahoo.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'americanexpress.com', 'dropbox.com', 'github.com', 'stackoverflow.com']

    async def check(self, url: str) -> Dict[str, Any]:
        try:
            domain = urlparse(url).hostname
            if not domain:
                return {'error': 'Invalid domain', 'suspicious': False}
            if domain in self.known_brands:
                return {'is_typosquatting': False, 'is_known_brand': True, 'suspicious': False}
            is_legitimate_subdomain = any((domain.endswith('.' + brand) or domain == brand for brand in self.known_brands))
            if is_legitimate_subdomain:
                return {'is_typosquatting': False, 'is_known_brand': True, 'suspicious': False}
            for brand in self.known_brands:
                if brand.count('.') > 1:
                    continue
                similarity = difflib.SequenceMatcher(None, domain, brand).ratio()
                if 0.8 < similarity < 1.0:
                    return {'is_typosquatting': True, 'target_brand': brand, 'similarity': round(similarity, 3), 'suspicious': True, 'reason': f'Domain similar to {brand} (similarity: {similarity:.1%})'}
            has_unicode = any((ord(c) > 127 for c in domain))
            has_brand_in_wrong_place = False
            for brand in self.known_brands:
                brand_name = brand.split('.')[0]
                if len(brand_name) <= 3:
                    continue
                if brand_name in domain and (not domain.endswith('.' + brand)) and (domain != brand):
                    has_brand_in_wrong_place = True
                    break
            suspicious = has_unicode or has_brand_in_wrong_place
            reasons = []
            if has_unicode:
                reasons.append('Contains non-ASCII characters (possible homograph attack)')
            if has_brand_in_wrong_place:
                reasons.append('Contains known brand name in suspicious position')
            return {'is_typosquatting': False, 'has_unicode_chars': has_unicode, 'has_brand_in_subdomain': has_brand_in_wrong_place, 'suspicious': suspicious, 'reason': '; '.join(reasons) if reasons else None}
        except Exception as e:
            return {'error': str(e), 'suspicious': False, 'reason': 'Typosquatting check failed'}

class EnhancedFeatureExtractor:
    URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'is.gd', 'shorte.st', 'cutt.ly', 'rb.gy', 'tiny.cc']

    @staticmethod
    def calculate_entropy(s: str) -> float:
        if not s:
            return 0.0
        entropy = 0.0
        for c in set(s):
            p = s.count(c) / len(s)
            entropy += -p * log2(p)
        return entropy

    async def extract(self, url: str) -> Dict[str, Any]:
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ''
            path = parsed.path or ''
            is_shortened = any((short in domain for short in self.URL_SHORTENERS))
            has_at_symbol = '@' in url
            subdomain_count = max(0, domain.count('.') - 1)
            has_port = parsed.port is not None
            unusual_port = parsed.port not in [None, 80, 443, 8080] if parsed.port else False
            domain_entropy = self.calculate_entropy(domain)
            letter_count = sum((c.isalpha() for c in domain))
            digit_count = sum((c.isdigit() for c in domain))
            digit_letter_ratio = digit_count / letter_count if letter_count > 0 else 0
            has_ip = bool(re.match('^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', domain))
            special_char_count = sum((1 for c in domain if not c.isalnum() and c != '.'))
            suspicious_path_tokens = ['login', 'verify', 'account', 'update', 'secure', 'signin']
            has_suspicious_path = any((token in path.lower() for token in suspicious_path_tokens))
            suspicious = False
            reasons = []
            if is_shortened:
                suspicious = True
                reasons.append('URL shortener detected')
            if has_at_symbol:
                suspicious = True
                reasons.append('Contains @ symbol (can hide real domain)')
            if subdomain_count > 3:
                suspicious = True
                reasons.append(f'Excessive subdomains ({subdomain_count})')
            if unusual_port:
                suspicious = True
                reasons.append(f'Unusual port number ({parsed.port})')
            if domain_entropy > 4.5:
                suspicious = True
                reasons.append(f'High domain entropy ({domain_entropy:.2f})')
            if digit_letter_ratio > 0.5:
                suspicious = True
                reasons.append(f'High digit-to-letter ratio ({digit_letter_ratio:.2f})')
            if has_ip:
                suspicious = True
                reasons.append('IP address used instead of domain name')
            return {'is_url_shortened': is_shortened, 'has_at_symbol': has_at_symbol, 'subdomain_count': subdomain_count, 'has_unusual_port': unusual_port, 'port': parsed.port, 'domain_entropy': round(domain_entropy, 3), 'digit_letter_ratio': round(digit_letter_ratio, 3), 'has_ip_address': has_ip, 'special_char_count': special_char_count, 'has_suspicious_path': has_suspicious_path, 'suspicious': suspicious, 'reason': '; '.join(reasons) if reasons else None}
        except Exception as e:
            return {'error': str(e), 'suspicious': False, 'reason': 'Enhanced feature extraction failed'}