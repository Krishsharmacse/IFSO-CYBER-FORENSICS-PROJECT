from sqlalchemy import Column, Integer, String, Text, DateTime
from database import Base
import datetime

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    status = Column(String, default="Pending")
    tool_used = Column(String)
    results = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
