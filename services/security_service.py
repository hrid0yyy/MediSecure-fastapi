"""
Security Threat Detection Service
Tracks failed login attempts and detects malicious activity patterns.
"""
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy.orm import Session
from config.redis_db import redis_client
from models.security_threat import SecurityThreat, ThreatType, ThreatLevel, AdminNotification
from models.blocked_ip import BlockedIP
import json
import logging

logger = logging.getLogger(__name__)

# Threat detection thresholds
FAILED_LOGIN_THRESHOLD = 5  # Max failed logins per minute
FAILED_LOGIN_WINDOW = 60  # Time window in seconds
MULTIPLE_ACCOUNTS_THRESHOLD = 3  # Max different accounts from same IP in window
MULTIPLE_ACCOUNTS_WINDOW = 300  # 5 minutes
AUTO_BLOCK_THRESHOLD = 10  # Auto-block after this many failed attempts


class ThreatDetectionService:
    """Service for detecting and tracking security threats"""
    
    @staticmethod
    async def track_failed_login(
        db: Session,
        ip_address: str,
        email: str,
        user_agent: Optional[str] = None
    ) -> dict:
        """
        Track a failed login attempt and detect suspicious patterns.
        Returns dict with 'should_block' and 'threat_detected' flags.
        """
        redis_key_failures = f"failed_login:{ip_address}"
        redis_key_accounts = f"attempted_accounts:{ip_address}"
        
        current_time = datetime.utcnow().timestamp()
        
        # Get recent failed login attempts (last minute)
        try:
            await redis_client.zadd(redis_key_failures, {str(current_time): current_time})
            await redis_client.expire(redis_key_failures, FAILED_LOGIN_WINDOW)
            
            # Remove old attempts outside the window
            cutoff_time = current_time - FAILED_LOGIN_WINDOW
            await redis_client.zremrangebyscore(redis_key_failures, 0, cutoff_time)
            
            # Count recent attempts
            recent_attempts = await redis_client.zcount(
                redis_key_failures,
                cutoff_time,
                current_time
            )
            
            # Track attempted email addresses
            await redis_client.sadd(redis_key_accounts, email)
            await redis_client.expire(redis_key_accounts, MULTIPLE_ACCOUNTS_WINDOW)
            attempted_accounts = await redis_client.smembers(redis_key_accounts)
            
            logger.info(f"IP {ip_address}: {recent_attempts} failed attempts, {len(attempted_accounts)} accounts tried")
            
        except Exception as e:
            logger.error(f"Redis error tracking failed login: {e}")
            # Fallback to database-only tracking
            recent_attempts = 1
            attempted_accounts = [email]
        
        # Detect threats
        threat_detected = False
        threat_level = ThreatLevel.LOW
        threat_type = ThreatType.FAILED_LOGIN
        should_block = False
        
        # Rule 1: Multiple failed logins in short time
        if recent_attempts >= FAILED_LOGIN_THRESHOLD:
            threat_detected = True
            threat_level = ThreatLevel.HIGH
            threat_type = ThreatType.BRUTE_FORCE
            
            if recent_attempts >= AUTO_BLOCK_THRESHOLD:
                should_block = True
                threat_level = ThreatLevel.CRITICAL
        
        # Rule 2: Same IP trying multiple accounts
        elif len(attempted_accounts) >= MULTIPLE_ACCOUNTS_THRESHOLD:
            threat_detected = True
            threat_level = ThreatLevel.MEDIUM
            threat_type = ThreatType.MULTIPLE_ACCOUNTS
            
            if len(attempted_accounts) >= 5:
                should_block = True
                threat_level = ThreatLevel.HIGH
        
        # Log threat to database if detected
        if threat_detected:
            await ThreatDetectionService._log_threat(
                db=db,
                ip_address=ip_address,
                threat_type=threat_type,
                threat_level=threat_level,
                attempted_emails=list(attempted_accounts),
                attempt_count=recent_attempts,
                should_block=should_block
            )
        
        return {
            "should_block": should_block,
            "threat_detected": threat_detected,
            "threat_level": threat_level.value if threat_detected else None,
            "attempt_count": recent_attempts,
            "attempted_accounts": len(attempted_accounts)
        }
    
    @staticmethod
    async def _log_threat(
        db: Session,
        ip_address: str,
        threat_type: ThreatType,
        threat_level: ThreatLevel,
        attempted_emails: List[str],
        attempt_count: int,
        should_block: bool
    ):
        """Log security threat to database and create admin notification"""
        
        # Check if threat already exists for this IP (within last hour)
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        existing_threat = db.query(SecurityThreat).filter(
            SecurityThreat.ip_address == ip_address,
            SecurityThreat.threat_type == threat_type,
            SecurityThreat.created_at >= one_hour_ago,
            SecurityThreat.is_resolved == False
        ).first()
        
        if existing_threat:
            # Update existing threat
            existing_threat.attempt_count = attempt_count
            existing_threat.threat_level = threat_level
            existing_threat.is_blocked = should_block
            existing_threat.attempted_emails = json.dumps(attempted_emails)
            existing_threat.updated_at = datetime.utcnow()
            threat = existing_threat
        else:
            # Create new threat record
            description = ThreatDetectionService._generate_threat_description(
                threat_type, attempt_count, len(attempted_emails)
            )
            
            threat = SecurityThreat(
                ip_address=ip_address,
                threat_type=threat_type,
                threat_level=threat_level,
                description=description,
                attempted_emails=json.dumps(attempted_emails),
                attempt_count=attempt_count,
                is_blocked=should_block
            )
            db.add(threat)
        
        db.commit()
        db.refresh(threat)
        
        # Auto-block IP if threshold exceeded
        if should_block:
            await ThreatDetectionService._auto_block_ip(db, ip_address, threat.id)
        
        # Create admin notification for high/critical threats
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            await ThreatDetectionService._create_admin_notification(
                db, threat, should_block
            )
        
        logger.warning(f"Security threat logged: {threat_type.value} from {ip_address} (Level: {threat_level.value})")
    
    @staticmethod
    async def _auto_block_ip(db: Session, ip_address: str, threat_id: int):
        """Automatically block an IP address"""
        
        # Check if already blocked
        existing_block = db.query(BlockedIP).filter(
            BlockedIP.ip_address == ip_address
        ).first()
        
        if existing_block:
            if not existing_block.is_active:
                existing_block.is_active = True
                existing_block.reason = f"Auto-blocked due to security threat (Threat ID: {threat_id})"
                existing_block.blocked_by = "system:auto-block"
                existing_block.updated_at = datetime.utcnow()
        else:
            blocked_ip = BlockedIP(
                ip_address=ip_address,
                reason=f"Auto-blocked due to security threat (Threat ID: {threat_id})",
                blocked_by="system:auto-block",
                is_active=True
            )
            db.add(blocked_ip)
        
        db.commit()
        logger.warning(f"IP {ip_address} has been auto-blocked (Threat ID: {threat_id})")
    
    @staticmethod
    async def _create_admin_notification(
        db: Session,
        threat: SecurityThreat,
        was_blocked: bool
    ):
        """Create notification for admins"""
        
        block_status = "and has been AUTO-BLOCKED" if was_blocked else ""
        
        notification = AdminNotification(
            threat_id=threat.id,
            title=f"🚨 {threat.threat_level.value.upper()} Security Threat Detected",
            message=f"IP {threat.ip_address} detected with {threat.threat_type.value} activity. "
                   f"{threat.attempt_count} attempts detected {block_status}. "
                   f"Please review immediately.",
            severity=threat.threat_level
        )
        
        db.add(notification)
        db.commit()
        
        logger.info(f"Admin notification created for threat {threat.id}")
    
    @staticmethod
    def _generate_threat_description(
        threat_type: ThreatType,
        attempt_count: int,
        account_count: int
    ) -> str:
        """Generate human-readable threat description"""
        
        if threat_type == ThreatType.BRUTE_FORCE:
            return f"Brute force attack detected: {attempt_count} failed login attempts within 1 minute"
        elif threat_type == ThreatType.MULTIPLE_ACCOUNTS:
            return f"Multiple account enumeration: Attempted {account_count} different accounts from same IP"
        elif threat_type == ThreatType.FAILED_LOGIN:
            return f"Repeated failed login attempts: {attempt_count} failures detected"
        else:
            return f"Suspicious activity detected: {attempt_count} attempts"
    
    @staticmethod
    async def clear_failed_attempts(ip_address: str):
        """Clear failed login tracking for an IP (e.g., after successful login)"""
        try:
            redis_key_failures = f"failed_login:{ip_address}"
            redis_key_accounts = f"attempted_accounts:{ip_address}"
            await redis_client.delete(redis_key_failures)
            await redis_client.delete(redis_key_accounts)
        except Exception as e:
            logger.error(f"Error clearing failed attempts: {e}")
    
    @staticmethod
    def get_active_threats(db: Session, hours: int = 24) -> List[SecurityThreat]:
        """Get all active threats from last N hours"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return db.query(SecurityThreat).filter(
            SecurityThreat.created_at >= cutoff_time,
            SecurityThreat.is_resolved == False
        ).order_by(SecurityThreat.created_at.desc()).all()
