from pydantic import BaseModel, Field
from datetime import datetime
from .models import ReportType

class ReportCreate(BaseModel):
    url: str
    type: ReportType
    description: str

class ReportResponse(BaseModel):
    id: str
    url: str
    type: ReportType
    description: str
    created_at: datetime

    class Config:
        from_attributes = True

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    conversation_history: list[ChatMessage] = Field(default_factory=list)

class ChatResponse(BaseModel):
    response: str