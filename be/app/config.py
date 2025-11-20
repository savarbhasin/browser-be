import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class Settings:
    API_PORT: int = int(os.getenv('API_PORT', '8000'))
    API_HOST: str = os.getenv('API_HOST', '0.0.0.0')
    API_LOG_LEVEL: str = os.getenv('API_LOG_LEVEL', 'info')
    MODEL_PATH: str = os.getenv('MODEL_PATH', '../models/url_model.joblib')
    CORS_ORIGINS: str = os.getenv('CORS_ORIGINS', 'http://localhost:5173,chrome-extension://*')
    DATABASE_URL: str = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/uss_db')
    GROQ_API_KEY: str = os.getenv('GROQ_API_KEY', '')
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    GOOGLE_SAFE_BROWSING_API_URL: str = os.getenv('GOOGLE_SAFE_BROWSING_API_URL', 'https://safebrowsing.googleapis.com/v4/threatMatches:find')
    SAFE_BROWSING_ENABLED: bool = os.getenv('SAFE_BROWSING_ENABLED', 'true').lower() == 'true'
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv('VIRUSTOTAL_API_KEY')
    PHISHTANK_APP_KEY: Optional[str] = os.getenv('PHISHTANK_APP_KEY')
settings = Settings()