from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from config.database import Base
from datetime import datetime

class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)  # IPv6 max length
    reason = Column(Text, nullable=True)  # Reason for blocking
    blocked_by = Column(String, nullable=False)  # Admin email/username who blocked it
    is_active = Column(Boolean, default=True, nullable=False)  # Can temporarily unblock
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
