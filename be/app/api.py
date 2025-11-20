from typing import Any, Dict, List, Optional
import asyncio
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, HttpUrl, Field
from .ml.model import UrlModel
from .ml.features import extract_features
from .config import settings
from .services.safe_browsing import SafeBrowsingService
from .services.enhanced_detection import DomainAgeChecker, SSLCertificateChecker, DNSChecker, TyposquattingChecker, EnhancedFeatureExtractor
from .services.reputation_checker import ReputationChecker
from .rate_limit import limiter, RATE_LIMITS, get_rate_limit_info
import os
router = APIRouter()
model = UrlModel(model_path=settings.MODEL_PATH)
safe_browsing_service = SafeBrowsingService()
domain_age_checker = DomainAgeChecker(suspicious_days=90)
ssl_checker = SSLCertificateChecker(timeout=5)
dns_checker = DNSChecker(timeout=5)
brands_file = os.path.join(os.path.dirname(__file__), 'data', 'known_brands.txt')
typosquat_checker = TyposquattingChecker(brands_file=brands_file if os.path.exists(brands_file) else None)
enhanced_feature_extractor = EnhancedFeatureExtractor()
virustotal_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
reputation_checker = ReputationChecker(virustotal_api_key=virustotal_key, timeout=10)

class UrlCheckRequest(BaseModel):
    url: HttpUrl

class UrlCheckResponse(BaseModel):
    url: str
    safe: bool
    ml_score: float = Field(..., description='ML model prediction score (0-1, higher = more suspicious)')
    ml_label: str = Field(..., description='ML model prediction label')
    safe_browsing: Dict[str, Any] = Field(..., description='Google Safe Browsing API result')
    features: Dict[str, Any] = Field(..., description='Extracted URL features')
    enhanced_checks: Optional[Dict[str, Any]] = Field(None, description='Enhanced detection results (domain age, SSL, DNS, typosquatting, etc.)')
    final_verdict: str = Field(..., description='Final safety verdict based on all checks')
    confidence: str = Field(..., description='Confidence level: high, medium, low')
    suspicious_signals: List[str] = Field(default_factory=list, description='List of suspicious signals detected')
    risk_score: int = Field(..., description='Comprehensive risk score (0-100, higher = more dangerous)', ge=0, le=100)

class BatchUrlCheckRequest(BaseModel):
    urls: List[HttpUrl] = Field(..., max_items=100, description='List of URLs to check (max 100)')

class BatchUrlCheckResponse(BaseModel):
    results: List[UrlCheckResponse]
    total_checked: int
    safe_count: int
    unsafe_count: int

@router.get('/health')
@limiter.limit(RATE_LIMITS['health'])
def health(request: Request, response: Response) -> Dict[str, str]:
    return {'status': 'ok', 'safe_browsing_enabled': safe_browsing_service.enabled}

@router.post('/check', response_model=UrlCheckResponse)
@limiter.limit(RATE_LIMITS['url_check'])
async def check_url(request: Request, response: Response, req: UrlCheckRequest) -> UrlCheckResponse:
    try:
        url_str = str(req.url)
        features = extract_features(url_str)
        ml_score = model.predict_proba(features)
        threshold = model.threshold
        ml_label = 'phishing' if ml_score >= threshold else 'safe'
        (safe_browsing_result, domain_age_result, ssl_result, dns_result, typosquat_result, enhanced_features, reputation_result) = await asyncio.gather(safe_browsing_service.check_url([url_str]), domain_age_checker.check(url_str), ssl_checker.check(url_str), dns_checker.check(url_str), typosquat_checker.check(url_str), enhanced_feature_extractor.extract(url_str), reputation_checker.check_all(url_str), return_exceptions=True)

        def safe_result(result, default):
            if isinstance(result, Exception):
                return {'error': str(result), 'suspicious': False, **default}
            if result is None:
                return {'error': 'Check returned None', 'suspicious': False, **default}
            if not isinstance(result, dict):
                return {'error': f'Invalid result type: {type(result)}', 'suspicious': False, **default}
            return result
        safe_browsing_result = safe_result(safe_browsing_result, {'safe': True})
        domain_age_result = safe_result(domain_age_result, {'suspicious': False})
        ssl_result = safe_result(ssl_result, {'suspicious': False})
        dns_result = safe_result(dns_result, {'suspicious': False})
        typosquat_result = safe_result(typosquat_result, {'suspicious': False})
        enhanced_features = safe_result(enhanced_features, {'suspicious': False})
        reputation_result = safe_result(reputation_result, {'overall_suspicious': False, 'detection_count': 0})
        suspicious_signals = []
        if not safe_browsing_result.get('safe', True):
            suspicious_signals.append('safe_browsing')
        if reputation_result.get('overall_suspicious', False):
            suspicious_signals.append('reputation_blacklist')
        if typosquat_result.get('is_typosquatting', False):
            suspicious_signals.append('typosquatting')
        if ml_score >= 0.9:
            suspicious_signals.append('ml_model_high_confidence')
        if domain_age_result.get('suspicious', False):
            suspicious_signals.append('new_domain')
        if ssl_result.get('suspicious', False):
            suspicious_signals.append('ssl_issues')
        if dns_result.get('suspicious', False):
            suspicious_signals.append('dns_anomaly')
        if enhanced_features.get('suspicious', False):
            suspicious_signals.append('url_features')
        if typosquat_result.get('has_unicode_chars', False):
            suspicious_signals.append('unicode_homograph')
        if typosquat_result.get('has_brand_in_subdomain', False):
            suspicious_signals.append('brand_in_subdomain')
        risk_score = 0
        if not safe_browsing_result.get('safe', True):
            risk_score += 30
        if reputation_result.get('overall_suspicious', False):
            risk_score += 30
        if typosquat_result.get('is_typosquatting', False):
            risk_score += 30
        if domain_age_result.get('suspicious', False):
            risk_score += 15
        if ssl_result.get('suspicious', False):
            risk_score += 15
        if typosquat_result.get('has_unicode_chars', False):
            risk_score += 15
        if typosquat_result.get('has_brand_in_subdomain', False):
            risk_score += 10
        if dns_result.get('suspicious', False):
            risk_score += 5
        if enhanced_features.get('suspicious', False):
            risk_score += 10
        if ml_score >= 0.9:
            risk_score += 15
        elif ml_score >= 0.7:
            risk_score += 5
        phishtank_data = reputation_result.get('phishtank') if reputation_result else None
        if phishtank_data and isinstance(phishtank_data, dict) and phishtank_data.get('in_database', False):
            risk_score += 20
        urlhaus_data = reputation_result.get('urlhaus') if reputation_result else None
        if urlhaus_data and isinstance(urlhaus_data, dict) and urlhaus_data.get('in_database', False):
            risk_score += 20
        vt_data = reputation_result.get('virustotal') if reputation_result else None
        vt_malicious = vt_data.get('malicious_count', 0) if vt_data and isinstance(vt_data, dict) else 0
        if vt_malicious > 5:
            risk_score += 20
        elif vt_malicious > 0:
            risk_score += 10
        risk_score = min(100, risk_score)
        is_flagged_by_security_service = False
        flagged_by_services = []
        if not safe_browsing_result.get('safe', True) and safe_browsing_result.get('threats', []):
            is_flagged_by_security_service = True
            flagged_by_services.append('Google Safe Browsing')
        if phishtank_data and isinstance(phishtank_data, dict) and phishtank_data.get('in_database', False):
            is_flagged_by_security_service = True
            flagged_by_services.append('PhishTank')
        if urlhaus_data and isinstance(urlhaus_data, dict) and urlhaus_data.get('in_database', False):
            is_flagged_by_security_service = True
            flagged_by_services.append('URLhaus')
        if vt_malicious > 3:
            is_flagged_by_security_service = True
            flagged_by_services.append(f'VirusTotal ({vt_malicious} engines)')
        if is_flagged_by_security_service:
            final_verdict = 'unsafe'
            confidence = 'high'
            risk_score = max(risk_score, 90)
            if 'reputation_service' not in suspicious_signals:
                suspicious_signals.append('reputation_service')
            if reputation_result and isinstance(reputation_result, dict):
                reputation_result['flagged_by_services'] = flagged_by_services
        elif risk_score >= 80:
            final_verdict = 'unsafe'
            confidence = 'high'
        elif risk_score >= 50:
            final_verdict = 'suspicious'
            confidence = 'high' if risk_score >= 65 else 'medium'
        else:
            final_verdict = 'safe'
            if risk_score < 15:
                confidence = 'high'
            elif risk_score < 35:
                confidence = 'medium'
            else:
                confidence = 'low'
        is_safe = final_verdict == 'safe'
        enhanced_checks = {'domain_age': domain_age_result, 'ssl_certificate': ssl_result, 'dns_records': dns_result, 'typosquatting': typosquat_result, 'enhanced_features': enhanced_features, 'reputation': reputation_result}
        return UrlCheckResponse(url=url_str, safe=is_safe, ml_score=float(ml_score), ml_label=ml_label, safe_browsing=safe_browsing_result, features=features, enhanced_checks=enhanced_checks, final_verdict=final_verdict, confidence=confidence, suspicious_signals=suspicious_signals, risk_score=risk_score)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'Error checking URL: {str(e)}')

@router.post('/check/batch', response_model=BatchUrlCheckResponse)
@limiter.limit(RATE_LIMITS['batch_check'])
async def check_urls_batch(request: Request, response: Response, req: BatchUrlCheckRequest) -> BatchUrlCheckResponse:
    try:
        results = []
        for url in req.urls:
            url_str = str(url)
            features = extract_features(url_str)
            ml_score = model.predict_proba(features)
            threshold = model.threshold
            ml_label = 'phishing' if ml_score >= threshold else 'safe'
            safe_browsing_result = await safe_browsing_service.check_url([url_str])
            risk_score = 0
            suspicious_signals = []
            if not safe_browsing_result.get('safe', True):
                risk_score += 30
                suspicious_signals.append('safe_browsing')
            if ml_score >= 0.9:
                risk_score += 15
                suspicious_signals.append('ml_model_high_confidence')
            elif ml_score >= 0.7:
                risk_score += 5
            risk_score = min(100, risk_score)
            if not safe_browsing_result.get('safe', True):
                final_verdict = 'unsafe'
                confidence = 'high'
                risk_score = max(risk_score, 90)
            elif risk_score >= 80:
                final_verdict = 'unsafe'
                confidence = 'high'
            elif risk_score >= 50:
                final_verdict = 'suspicious'
                confidence = 'high' if risk_score >= 65 else 'medium'
            else:
                final_verdict = 'safe'
                if risk_score < 15:
                    confidence = 'high'
                elif risk_score < 35:
                    confidence = 'medium'
                else:
                    confidence = 'low'
            is_safe = final_verdict == 'safe'
            results.append(UrlCheckResponse(url=url_str, safe=is_safe, ml_score=float(ml_score), ml_label=ml_label, safe_browsing=safe_browsing_result, features=features, final_verdict=final_verdict, confidence=confidence, suspicious_signals=suspicious_signals, risk_score=risk_score))
        safe_count = sum((1 for r in results if r.safe))
        unsafe_count = len(results) - safe_count
        return BatchUrlCheckResponse(results=results, total_checked=len(results), safe_count=safe_count, unsafe_count=unsafe_count)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'Error checking URLs: {str(e)}')

@router.get('/info')
@limiter.limit(RATE_LIMITS['health'])
def info(request: Request, response: Response) -> Dict[str, Any]:
    return {'name': 'URL Safety Checker API', 'version': '2.0.0', 'features': {'ml_model': True, 'google_safe_browsing': safe_browsing_service.enabled, 'batch_processing': True, 'domain_age_checking': True, 'ssl_validation': True, 'dns_analysis': True, 'typosquatting_detection': True, 'reputation_checking': True, 'enhanced_url_features': True, 'rate_limiting': True}, 'detection_techniques': {'ml_threshold': model.threshold, 'domain_age_threshold_days': domain_age_checker.suspicious_days, 'brands_database_size': len(typosquat_checker.known_brands), 'reputation_services': ['PhishTank', 'URLhaus'] + (['VirusTotal'] if virustotal_key else [])}, 'safe_browsing_configured': safe_browsing_service.api_key is not None, 'virustotal_configured': virustotal_key is not None}

@router.get('/rate-limits')
@limiter.limit(RATE_LIMITS['health'])
def rate_limits_info(request: Request, response: Response) -> Dict[str, Any]:
    return get_rate_limit_info()