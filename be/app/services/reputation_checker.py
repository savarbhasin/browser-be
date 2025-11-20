import aiohttp
import hashlib
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, quote
from app.config import settings

class ReputationChecker:

    def __init__(self, virustotal_api_key: Optional[str]=None, timeout: int=10):
        self.virustotal_api_key = virustotal_api_key
        self.timeout = timeout

    async def check_all(self, url: str) -> Dict[str, Any]:
        results = {'phishtank': None, 'urlhaus': None, 'virustotal': None, 'overall_suspicious': False, 'detection_count': 0, 'reasons': []}
        import asyncio
        tasks = [self.check_phishtank(url), self.check_urlhaus(url)]
        if self.virustotal_api_key:
            tasks.append(self.check_virustotal(url))
        try:
            check_results = await asyncio.gather(*tasks, return_exceptions=True)
            if not isinstance(check_results[0], Exception):
                results['phishtank'] = check_results[0]
                if check_results[0].get('in_database'):
                    results['overall_suspicious'] = True
                    results['detection_count'] += 1
                    results['reasons'].append('Listed in PhishTank')
            if not isinstance(check_results[1], Exception):
                results['urlhaus'] = check_results[1]
                if check_results[1].get('in_database'):
                    results['overall_suspicious'] = True
                    results['detection_count'] += 1
                    results['reasons'].append('Listed in URLhaus')
            if len(check_results) > 2 and (not isinstance(check_results[2], Exception)):
                results['virustotal'] = check_results[2]
                if check_results[2].get('malicious_count', 0) > 0:
                    results['overall_suspicious'] = True
                    results['detection_count'] += 1
                    results['reasons'].append(f"Flagged by {check_results[2]['malicious_count']} VirusTotal engines")
        except Exception as e:
            results['error'] = str(e)
        return results

    async def check_phishtank(self, url: str) -> Dict[str, Any]:
        try:
            api_url = 'https://checkurl.phishtank.com/checkurl/'
            encoded_url = quote(url, safe='')
            data = {'url': encoded_url, 'format': 'json', 'app_key': settings.PHISHTANK_APP_KEY}
            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, data=data, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        result = await response.json()
                        if 'results' in result:
                            in_database = result['results'].get('in_database', False)
                            verified = result['results'].get('verified', False)
                            return {'in_database': in_database, 'verified': verified, 'suspicious': in_database and verified}
                    return {'in_database': False, 'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'in_database': False, 'error': str(e)}

    async def check_urlhaus(self, url: str) -> Dict[str, Any]:
        try:
            api_url = 'https://urlhaus-api.abuse.ch/v1/url/'
            data = {'url': url}
            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, data=data, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        result = await response.json()
                        if result.get('query_status') == 'ok':
                            return {'in_database': True, 'threat': result.get('threat', 'unknown'), 'tags': result.get('tags', []), 'suspicious': True}
                        else:
                            return {'in_database': False, 'suspicious': False}
                    return {'in_database': False, 'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'in_database': False, 'error': str(e)}

    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        if not self.virustotal_api_key:
            return {'error': 'VirusTotal API key not configured', 'malicious_count': 0}
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            api_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            headers = {'x-apikey': self.virustotal_api_key}
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, headers=headers, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        result = await response.json()
                        stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total_engines = sum(stats.values())
                        return {'malicious_count': malicious, 'suspicious_count': suspicious, 'total_engines': total_engines, 'detection_ratio': f'{malicious}/{total_engines}', 'suspicious': malicious > 0 or suspicious > 2}
                    elif response.status == 404:
                        return await self._submit_url_to_virustotal(url)
                    return {'error': f'HTTP {response.status}', 'malicious_count': 0}
        except Exception as e:
            return {'error': str(e), 'malicious_count': 0}

    async def _submit_url_to_virustotal(self, url: str) -> Dict[str, Any]:
        try:
            api_url = 'https://www.virustotal.com/api/v3/urls'
            headers = {'x-apikey': self.virustotal_api_key}
            data = {'url': url}
            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, headers=headers, data=data, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        return {'submitted': True, 'message': 'URL submitted for scanning', 'malicious_count': 0, 'note': 'Results will be available shortly'}
                    return {'error': f'Failed to submit URL: HTTP {response.status}', 'malicious_count': 0}
        except Exception as e:
            return {'error': str(e), 'malicious_count': 0}