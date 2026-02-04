from fastapi import APIRouter, Depends, HTTPException, status, Query
import sys
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Optional
from datetime import datetime, timedelta
from config.database import get_db
from models.user import User, UserDevice, UserRole
from models.audit import AuditLog
from models.blocked_ip import BlockedIP
from models.security_threat import SecurityThreat, AdminNotification, ThreatLevel, ThreatType
from schemas.user import UserResponse
from utils.security import get_current_user
import json

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


def get_admin_user(current_user: User = Depends(get_current_user)):
    """Dependency to check if current user is an admin"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    role: Optional[UserRole] = Query(None, description="Filter by user role"),
    verified: Optional[bool] = Query(None, description="Filter by verification status"),
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get paginated list of all users (admin only).
    Supports filtering by role and verification status.
    """
    query = db.query(User)
    
    if role:
        query = query.filter(User.role == role)
    
    if verified is not None:
        query = query.filter(User.is_verified == verified)
    
    users = query.offset(skip).limit(limit).all()
    
    return [
        UserResponse(
            id=user.id,
            email=user.email,
            role=user.role,
            is_verified=user.is_verified
        )
        for user in users
    ]


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user_by_id(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get specific user details by ID (admin only).
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        is_verified=user.is_verified
    )


@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    new_role: UserRole,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Update a user's role (admin only).
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own role"
        )
    
    user.role = new_role
    db.commit()
    
    return {"message": f"User role updated to {new_role.value}"}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Delete a user account (admin only).
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    # Delete related devices first
    db.query(UserDevice).filter(UserDevice.user_id == user_id).delete()
    
    # Delete user
    db.delete(user)
    db.commit()
    
    return {"message": "User deleted successfully"}


@router.get("/audit-logs")
async def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    status: Optional[str] = Query(None, description="Filter by status (SUCCESS/FAILURE)"),
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get paginated audit logs (admin only).
    Supports filtering by user, action, and status.
    """
    query = db.query(AuditLog)
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if action:
        query = query.filter(AuditLog.action == action.upper())
    
    if status:
        query = query.filter(AuditLog.status == status.upper())
    
    # Order by most recent first
    query = query.order_by(desc(AuditLog.created_at))
    
    total = query.count()
    logs = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "logs": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "resource": log.resource,
                "resource_id": log.resource_id,
                "ip_address": log.ip_address,
                "status": log.status,
                "details": log.details,
                "created_at": log.created_at.isoformat() if log.created_at else None
            }
            for log in logs
        ]
    }


@router.get("/stats")
async def get_dashboard_stats(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get dashboard statistics (admin only).
    Returns counts of users, devices, and recent activity.
    """
    # Total users count
    total_users = db.query(func.count(User.id)).scalar()
    
    # Verified users count
    verified_users = db.query(func.count(User.id)).filter(User.is_verified == True).scalar()
    
    # Users by role
    users_by_role = db.query(
        User.role,
        func.count(User.id)
    ).group_by(User.role).all()
    
    # Total devices
    total_devices = db.query(func.count(UserDevice.id)).scalar()
    
    # Recent audit logs (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_actions = db.query(func.count(AuditLog.id)).filter(
        AuditLog.created_at >= yesterday
    ).scalar()
    
    # Failed login attempts (last 24 hours)
    failed_logins = db.query(func.count(AuditLog.id)).filter(
        AuditLog.action == "LOGIN",
        AuditLog.status == "FAILURE",
        AuditLog.created_at >= yesterday
    ).scalar()
    
    return {
        "users": {
            "total": total_users,
            "verified": verified_users,
            "by_role": {role.value: count for role, count in users_by_role}
        },
        "devices": {
            "total": total_devices
        },
        "activity_last_24h": {
            "total_actions": recent_actions,
            "failed_logins": failed_logins
        }
    }


@router.get("/audit-logs/user/{user_id}")
async def get_user_audit_logs(
    user_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get audit logs for a specific user (admin only).
    """
    # Check if user exists
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    query = db.query(AuditLog).filter(AuditLog.user_id == user_id)
    query = query.order_by(desc(AuditLog.created_at))
    
    total = query.count()
    logs = query.offset(skip).limit(limit).all()
    
    return {
        "user_id": user_id,
        "user_email": user.email,
        "total": total,
        "logs": [
            {
                "id": log.id,
                "action": log.action,
                "resource": log.resource,
                "ip_address": log.ip_address,
                "status": log.status,
                "created_at": log.created_at.isoformat() if log.created_at else None
            }
            for log in logs
        ]
    }


# ============ IP BLOCKING ENDPOINTS ============

@router.post("/blocked-ips")
async def block_ip_address(
    ip_address: str,
    reason: Optional[str] = None,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Block an IP address from accessing the API (admin only).
    """
    # Validate IP address format (basic validation)
    if not ip_address or ip_address == "unknown":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IP address"
        )
    
    # Check if IP is already blocked
    existing = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
    if existing:
        if existing.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"IP address {ip_address} is already blocked"
            )
        else:
            # Reactivate previously blocked IP
            existing.is_active = True
            existing.reason = reason if reason else existing.reason
            existing.blocked_by = admin_user.email
            existing.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(existing)
            return {
                "message": "IP address reactivated in blocklist",
                "blocked_ip": {
                    "id": existing.id,
                    "ip_address": existing.ip_address,
                    "reason": existing.reason,
                    "blocked_by": existing.blocked_by,
                    "is_active": existing.is_active,
                    "created_at": existing.created_at.isoformat(),
                    "updated_at": existing.updated_at.isoformat()
                }
            }
    
    # Create new blocked IP entry
    blocked_ip = BlockedIP(
        ip_address=ip_address,
        reason=reason,
        blocked_by=admin_user.email,
        is_active=True
    )
    
    db.add(blocked_ip)
    db.commit()
    db.refresh(blocked_ip)
    
    return {
        "message": "IP address successfully blocked",
        "blocked_ip": {
            "id": blocked_ip.id,
            "ip_address": blocked_ip.ip_address,
            "reason": blocked_ip.reason,
            "blocked_by": blocked_ip.blocked_by,
            "is_active": blocked_ip.is_active,
            "created_at": blocked_ip.created_at.isoformat(),
            "updated_at": blocked_ip.updated_at.isoformat()
        }
    }


@router.get("/blocked-ips")
async def list_blocked_ips(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get list of all blocked IP addresses (admin only).
    """
    query = db.query(BlockedIP)
    
    if is_active is not None:
        query = query.filter(BlockedIP.is_active == is_active)
    
    query = query.order_by(desc(BlockedIP.created_at))
    
    total = query.count()
    blocked_ips = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "blocked_ips": [
            {
                "id": ip.id,
                "ip_address": ip.ip_address,
                "reason": ip.reason,
                "blocked_by": ip.blocked_by,
                "is_active": ip.is_active,
                "created_at": ip.created_at.isoformat(),
                "updated_at": ip.updated_at.isoformat()
            }
            for ip in blocked_ips
        ]
    }


@router.get("/blocked-ips/{ip_id}")
async def get_blocked_ip(
    ip_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get details of a specific blocked IP (admin only).
    """
    blocked_ip = db.query(BlockedIP).filter(BlockedIP.id == ip_id).first()
    
    if not blocked_ip:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blocked IP not found"
        )
    
    return {
        "id": blocked_ip.id,
        "ip_address": blocked_ip.ip_address,
        "reason": blocked_ip.reason,
        "blocked_by": blocked_ip.blocked_by,
        "is_active": blocked_ip.is_active,
        "created_at": blocked_ip.created_at.isoformat(),
        "updated_at": blocked_ip.updated_at.isoformat()
    }


@router.put("/blocked-ips/{ip_id}")
async def update_blocked_ip(
    ip_id: int,
    reason: Optional[str] = None,
    is_active: Optional[bool] = None,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Update a blocked IP entry (admin only).
    Can modify reason and active status.
    """
    blocked_ip = db.query(BlockedIP).filter(BlockedIP.id == ip_id).first()
    
    if not blocked_ip:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blocked IP not found"
        )
    
    # Update fields
    if reason is not None:
        blocked_ip.reason = reason
    
    if is_active is not None:
        blocked_ip.is_active = is_active
    
    blocked_ip.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(blocked_ip)
    
    return {
        "message": "Blocked IP updated successfully",
        "blocked_ip": {
            "id": blocked_ip.id,
            "ip_address": blocked_ip.ip_address,
            "reason": blocked_ip.reason,
            "blocked_by": blocked_ip.blocked_by,
            "is_active": blocked_ip.is_active,
            "created_at": blocked_ip.created_at.isoformat(),
            "updated_at": blocked_ip.updated_at.isoformat()
        }
    }


@router.delete("/blocked-ips/{ip_id}")
async def unblock_ip_address(
    ip_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Unblock an IP address by setting is_active to False (admin only).
    Does not permanently delete the record for audit purposes.
    """
    blocked_ip = db.query(BlockedIP).filter(BlockedIP.id == ip_id).first()
    
    if not blocked_ip:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blocked IP not found"
        )
    
    # Set to inactive instead of deleting
    blocked_ip.is_active = False
    blocked_ip.updated_at = datetime.utcnow()
    
    db.commit()
    
    return {
        "message": f"IP address {blocked_ip.ip_address} has been unblocked",
        "ip_address": blocked_ip.ip_address
    }


@router.delete("/blocked-ips/{ip_id}/permanent")
async def permanently_delete_blocked_ip(
    ip_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Permanently delete a blocked IP record (admin only).
    Use with caution - this action cannot be undone.
    """
    blocked_ip = db.query(BlockedIP).filter(BlockedIP.id == ip_id).first()
    
    if not blocked_ip:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Blocked IP not found"
        )
    
    ip_address = blocked_ip.ip_address
    db.delete(blocked_ip)
    db.commit()
    
    return {
        "message": f"IP address {ip_address} has been permanently removed from blocklist",
        "ip_address": ip_address
    }


# ============ SECURITY THREAT MONITORING ENDPOINTS ============

@router.get("/security-threats")
async def list_security_threats(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    threat_level: Optional[ThreatLevel] = Query(None),
    threat_type: Optional[ThreatType] = Query(None),
    is_resolved: Optional[bool] = Query(None),
    hours: int = Query(24, ge=1, le=168, description="Filter by hours (1-168)"),
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get list of detected security threats (admin only).
    Shows malicious activity patterns and auto-blocked IPs.
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(SecurityThreat).filter(SecurityThreat.created_at >= cutoff_time)
    
    if threat_level:
        query = query.filter(SecurityThreat.threat_level == threat_level)
    
    if threat_type:
        query = query.filter(SecurityThreat.threat_type == threat_type)
    
    if is_resolved is not None:
        query = query.filter(SecurityThreat.is_resolved == is_resolved)
    
    query = query.order_by(desc(SecurityThreat.created_at))
    
    total = query.count()
    threats = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "hours": hours,
        "threats": [
            {
                "id": threat.id,
                "ip_address": threat.ip_address,
                "threat_type": threat.threat_type.value,
                "threat_level": threat.threat_level.value,
                "description": threat.description,
                "attempted_emails": json.loads(threat.attempted_emails) if threat.attempted_emails else [],
                "attempt_count": threat.attempt_count,
                "is_blocked": threat.is_blocked,
                "is_resolved": threat.is_resolved,
                "resolved_by": threat.resolved_by,
                "resolved_at": threat.resolved_at.isoformat() if threat.resolved_at else None,
                "created_at": threat.created_at.isoformat(),
                "updated_at": threat.updated_at.isoformat()
            }
            for threat in threats
        ]
    }


@router.get("/security-threats/{threat_id}")
async def get_security_threat(
    threat_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific security threat (admin only).
    """
    threat = db.query(SecurityThreat).filter(SecurityThreat.id == threat_id).first()
    
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security threat not found"
        )
    
    return {
        "id": threat.id,
        "ip_address": threat.ip_address,
        "threat_type": threat.threat_type.value,
        "threat_level": threat.threat_level.value,
        "description": threat.description,
        "attempted_emails": json.loads(threat.attempted_emails) if threat.attempted_emails else [],
        "attempt_count": threat.attempt_count,
        "is_blocked": threat.is_blocked,
        "is_resolved": threat.is_resolved,
        "resolved_by": threat.resolved_by,
        "resolved_at": threat.resolved_at.isoformat() if threat.resolved_at else None,
        "created_at": threat.created_at.isoformat(),
        "updated_at": threat.updated_at.isoformat()
    }


@router.put("/security-threats/{threat_id}/resolve")
async def resolve_security_threat(
    threat_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Mark a security threat as resolved (admin only).
    """
    threat = db.query(SecurityThreat).filter(SecurityThreat.id == threat_id).first()
    
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security threat not found"
        )
    
    threat.is_resolved = True
    threat.resolved_by = admin_user.email
    threat.resolved_at = datetime.utcnow()
    
    db.commit()
    
    return {
        "message": "Security threat marked as resolved",
        "threat_id": threat_id,
        "resolved_by": admin_user.email
    }


@router.get("/security-threats/stats/summary")
async def get_security_threat_stats(
    hours: int = Query(24, ge=1, le=168),
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get summary statistics of security threats (admin only).
    """
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Total threats
    total_threats = db.query(SecurityThreat).filter(
        SecurityThreat.created_at >= cutoff_time
    ).count()
    
    # Threats by level
    threats_by_level = db.query(
        SecurityThreat.threat_level,
        func.count(SecurityThreat.id)
    ).filter(
        SecurityThreat.created_at >= cutoff_time
    ).group_by(SecurityThreat.threat_level).all()
    
    # Threats by type
    threats_by_type = db.query(
        SecurityThreat.threat_type,
        func.count(SecurityThreat.id)
    ).filter(
        SecurityThreat.created_at >= cutoff_time
    ).group_by(SecurityThreat.threat_type).all()
    
    # Auto-blocked IPs count
    auto_blocked = db.query(SecurityThreat).filter(
        SecurityThreat.created_at >= cutoff_time,
        SecurityThreat.is_blocked == True
    ).count()
    
    # Unresolved threats
    unresolved = db.query(SecurityThreat).filter(
        SecurityThreat.created_at >= cutoff_time,
        SecurityThreat.is_resolved == False
    ).count()
    
    # Top attacking IPs
    top_ips = db.query(
        SecurityThreat.ip_address,
        func.count(SecurityThreat.id).label('count'),
        func.max(SecurityThreat.threat_level).label('max_level')
    ).filter(
        SecurityThreat.created_at >= cutoff_time
    ).group_by(SecurityThreat.ip_address).order_by(desc('count')).limit(10).all()
    
    return {
        "period_hours": hours,
        "total_threats": total_threats,
        "auto_blocked_ips": auto_blocked,
        "unresolved_threats": unresolved,
        "by_level": {level.value: count for level, count in threats_by_level},
        "by_type": {type_.value: count for type_, count in threats_by_type},
        "top_attacking_ips": [
            {
                "ip_address": ip,
                "threat_count": count,
                "max_threat_level": max_level.value
            }
            for ip, count, max_level in top_ips
        ]
    }


# ============ ADMIN NOTIFICATION ENDPOINTS ============

@router.get("/notifications")
async def list_admin_notifications(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    is_read: Optional[bool] = Query(None),
    severity: Optional[ThreatLevel] = Query(None),
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Get list of admin notifications (admin only).
    """
    query = db.query(AdminNotification)
    
    if is_read is not None:
        query = query.filter(AdminNotification.is_read == is_read)
    
    if severity:
        query = query.filter(AdminNotification.severity == severity)
    
    query = query.order_by(desc(AdminNotification.created_at))
    
    total = query.count()
    unread_count = db.query(AdminNotification).filter(
        AdminNotification.is_read == False
    ).count()
    
    notifications = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "unread_count": unread_count,
        "skip": skip,
        "limit": limit,
        "notifications": [
            {
                "id": notif.id,
                "threat_id": notif.threat_id,
                "title": notif.title,
                "message": notif.message,
                "severity": notif.severity.value,
                "is_read": notif.is_read,
                "read_by": notif.read_by,
                "read_at": notif.read_at.isoformat() if notif.read_at else None,
                "created_at": notif.created_at.isoformat()
            }
            for notif in notifications
        ]
    }


@router.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Mark a notification as read (admin only).
    """
    notification = db.query(AdminNotification).filter(
        AdminNotification.id == notification_id
    ).first()
    
    if not notification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found"
        )
    
    notification.is_read = True
    notification.read_by = admin_user.email
    notification.read_at = datetime.utcnow()
    
    db.commit()
    
    return {
        "message": "Notification marked as read",
        "notification_id": notification_id
    }


@router.put("/notifications/read-all")
async def mark_all_notifications_read(
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Mark all unread notifications as read (admin only).
    """
    unread_notifications = db.query(AdminNotification).filter(
        AdminNotification.is_read == False
    ).all()
    
    count = len(unread_notifications)
    
    for notification in unread_notifications:
        notification.is_read = True
        notification.read_by = admin_user.email
        notification.read_at = datetime.utcnow()
    
    db.commit()
    
    return {
        "message": f"Marked {count} notifications as read",
        "count": count
    }


@router.delete("/notifications/{notification_id}")
async def delete_notification(
    notification_id: int,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """
    Delete a notification (admin only).
    """
    notification = db.query(AdminNotification).filter(
        AdminNotification.id == notification_id
    ).first()
    
    if not notification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found"
        )
    
    db.delete(notification)
    db.commit()
    
    return {
        "message": "Notification deleted",
        "notification_id": notification_id
    }


