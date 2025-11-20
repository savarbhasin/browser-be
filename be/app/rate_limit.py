from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, Response
from fastapi.responses import JSONResponse
import re

def _rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    limit_detail = str(exc.detail) if exc.detail else 'Unknown limit'
    retry_after = '60'
    if 'minute' in limit_detail.lower():
        match = re.search('(\\d+)\\s*per\\s*\\d*\\s*minute', limit_detail)
        if match:
            retry_after = '60'
    elif 'hour' in limit_detail.lower():
        retry_after = '3600'
    return JSONResponse(status_code=429, content={'error': 'Rate limit exceeded', 'message': 'Too many requests. Please slow down and try again later.', 'detail': limit_detail, 'retry_after_seconds': int(retry_after), 'hint': 'Rate limits help ensure fair usage for all users. Consider implementing caching on your end.'}, headers={'Retry-After': retry_after, 'X-RateLimit-Reset': retry_after})
limiter = Limiter(key_func=get_remote_address, default_limits=['100 per minute', '1000 per hour'], storage_uri='memory://', strategy='fixed-window', headers_enabled=True, swallow_errors=False)
RATE_LIMITS = {'url_check': '30 per minute', 'batch_check': '10 per minute', 'report_create': '20 per minute', 'report_read': '60 per minute', 'chat': '10 per minute', 'health': '100 per minute'}
RATE_LIMIT_DESCRIPTIONS = {'url_check': 'Single URL safety checks are limited to 30 requests per minute to prevent abuse', 'batch_check': 'Batch URL checks are limited to 10 requests per minute (each can check up to 100 URLs)', 'report_create': 'Creating reports is limited to 20 per minute', 'report_read': 'Reading reports is limited to 60 per minute', 'chat': 'AI chat is limited to 10 requests per minute due to API costs', 'health': 'Health check endpoint is rate-limited to 100 requests per minute'}

def get_rate_limit_info() -> dict:
    return {'strategy': 'fixed-window', 'storage': 'memory', 'key': 'client_ip', 'default_limits': {'per_minute': 100, 'per_hour': 1000}, 'endpoint_limits': RATE_LIMITS, 'descriptions': RATE_LIMIT_DESCRIPTIONS, 'headers': {'X-RateLimit-Limit': 'Maximum requests allowed', 'X-RateLimit-Remaining': 'Requests remaining in current window', 'X-RateLimit-Reset': 'Time when the rate limit resets (Unix timestamp)', 'Retry-After': 'Seconds to wait before retrying (on 429 errors)'}}