import httpx
from typing import Dict, List, Optional, Any
from ..config import settings

class SafeBrowsingService:

    def __init__(self):
        self.api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.api_url = settings.GOOGLE_SAFE_BROWSING_API_URL
        self.enabled = settings.SAFE_BROWSING_ENABLED and self.api_key is not None

    async def check_url(self, urls: List[str]) -> Dict[str, Any]:
        if not self.enabled:
            return {'safe': True, 'threats': [], 'error': 'Safe Browsing API not configured or disabled'}
        try:
            payload = {'client': {'clientId': 'uss-project', 'clientVersion': '1.0.0'}, 'threatInfo': {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'], 'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'], 'threatEntries': [{'url': url} for url in urls]}}
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(f'{self.api_url}?key={self.api_key}', json=payload)
                response.raise_for_status()
                result = response.json()
            if 'matches' in result and len(result['matches']) > 0:
                threats = [{'threatType': match.get('threatType', 'UNKNOWN'), 'platformType': match.get('platformType', 'UNKNOWN'), 'threatEntryType': match.get('threatEntryType', 'UNKNOWN'), 'threat': match.get('threat', 'UNKNOWN')} for match in result['matches']]
                return {'safe': False, 'threats': threats, 'error': None}
            else:
                return {'safe': True, 'threats': [], 'error': None}
        except httpx.HTTPStatusError as e:
            return {'safe': True, 'threats': [], 'error': f'Safe Browsing API error: {e.response.status_code} - {e.response.text}'}
        except httpx.RequestError as e:
            return {'safe': True, 'threats': [], 'error': f'Network error connecting to Safe Browsing API: {str(e)}'}
        except Exception as e:
            return {'safe': True, 'threats': [], 'error': f'Unexpected error: {str(e)}'}

    async def check_urls(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        return await self.check_url(urls)