import uvicorn
from app.config import settings
from dotenv import load_dotenv
if __name__ == '__main__':
    load_dotenv()
    uvicorn.run('app.main:app', host=settings.API_HOST, port=settings.API_PORT, log_level=settings.API_LOG_LEVEL, reload=True)