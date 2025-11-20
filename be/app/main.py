from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from .api import router as api_router
from .routes import reports, chat
from .config import settings
from .database import init_db
from .rate_limit import limiter, _rate_limit_exceeded_handler
app = FastAPI(title='URL Safety Checker API', description='FastAPI server for checking URL safety using ML algorithms and Google Safe Browsing API', version='1.0.0')
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

@app.middleware('http')
async def enforce_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    if request.url.scheme == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=86400; includeSubDomains'
    return response

@app.on_event('startup')
def startup_event():
    init_db()
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True, allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allow_headers=['*'], expose_headers=['*'])
app.include_router(api_router, prefix='/api', tags=['url-check'])
app.include_router(reports.router, prefix='/api/reports', tags=['reports'])
app.include_router(chat.router, prefix='/api/chat', tags=['chat'])

@app.get('/')
def root():
    return {'message': 'URL Safety Checker API', 'docs': '/docs', 'health': '/api/health'}