from fastapi import APIRouter, Request, Response
from ..schemas import ChatRequest, ChatResponse
from ..services.groq_service import groq_service
from ..rate_limit import limiter, RATE_LIMITS
router = APIRouter()

@router.post('/', response_model=ChatResponse)
@limiter.limit(RATE_LIMITS['chat'])
async def chat(request: Request, response: Response, chat_request: ChatRequest):
    result = await groq_service.chat(chat_request.message, chat_request.conversation_history)
    return ChatResponse(response=result)