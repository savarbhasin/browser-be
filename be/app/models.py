from sqlalchemy import Column, String, Text, DateTime, Enum
from sqlalchemy.sql import func
import uuid
import enum
from .database import Base

class ReportType(str, enum.Enum):
    TRUE_POSITIVE = 'true_positive'
    TRUE_NEGATIVE = 'true_negative'
    FALSE_POSITIVE = 'false_positive'
    FALSE_NEGATIVE = 'false_negative'

class Report(Base):
    __tablename__ = 'reports'
    id = Column(String, primary_key=True, default=lambda : str(uuid.uuid4()))
    url = Column(Text, nullable=False)
    type = Column(Enum(ReportType), nullable=False)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())