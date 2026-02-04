from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Enum
from config.database import Base
from datetime import datetime
import enum

class ThreatLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(str, enum.Enum):
    FAILED_LOGIN = "failed_login"
    MULTIPLE_ACCOUNTS = "multiple_accounts"
    BRUTE_FORCE = "brute_force"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"

class SecurityThreat(Base):
    """
    Tracks detected security threats and malicious activities.
    """
    __tablename__ = "security_threats"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), index=True, nullable=False)
    threat_type = Column(Enum(ThreatType), nullable=False)
    threat_level = Column(Enum(ThreatLevel), nullable=False)
    description = Column(Text, nullable=False)
    attempted_emails = Column(Text, nullable=True)  # JSON array of attempted emails
    attempt_count = Column(Integer, default=1)
    is_blocked = Column(Boolean, default=False)  # Whether IP was auto-blocked
    is_resolved = Column(Boolean, default=False)  # Admin marked as resolved
    resolved_by = Column(String, nullable=True)  # Admin who resolved
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AdminNotification(Base):
    """
    Notifications for admins about security threats.
    """
    __tablename__ = "admin_notifications"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(Integer, nullable=True)  # Link to SecurityThreat if applicable
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(Enum(ThreatLevel), nullable=False)
    is_read = Column(Boolean, default=False)
    read_by = Column(String, nullable=True)  # Admin email who read it
    read_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
