from groq import Groq
from ..config import settings
from typing import List

class GroqService:

    def __init__(self):
        self.client = Groq(api_key=settings.GROQ_API_KEY) if settings.GROQ_API_KEY else None
        self.enabled = bool(settings.GROQ_API_KEY)

    async def chat(self, message: str, conversation_history: List[dict]=None) -> str:
        if not self.enabled:
            return 'AI chat is not configured. Please set GROQ_API_KEY in environment variables.'
        try:
            messages = [{'role': 'system', 'content': 'You are a helpful assistant specialized in cybersecurity and phishing detection. You help users understand URL safety, phishing techniques, and online security best practices.'}]
            if conversation_history:
                for msg in conversation_history:
                    messages.append({'role': msg.role if hasattr(msg, 'role') else msg.get('role', 'user'), 'content': msg.content if hasattr(msg, 'content') else msg.get('content', '')})
            messages.append({'role': 'user', 'content': message})
            chat_completion = self.client.chat.completions.create(messages=messages, model='llama-3.1-8b-instant', temperature=0.7, max_tokens=1024)
            return chat_completion.choices[0].message.content
        except Exception as e:
            return f'Error: {str(e)}'
groq_service = GroqService()