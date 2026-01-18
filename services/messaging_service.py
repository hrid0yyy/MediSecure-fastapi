from sqlalchemy.orm import Session
from datetime import datetime
from typing import List, Optional
from fastapi import HTTPException, status
from models.message import Message, MessageAttachment
from schemas.message import MessageCreate
from utils.encryption import encrypt_data, decrypt_data
import logging

logger = logging.getLogger(__name__)


def safe_decrypt(encrypted_content: str) -> str:
    """Safely decrypt content, returning placeholder if decryption fails"""
    try:
        return decrypt_data(encrypted_content)
    except Exception as e:
        logger.warning(f"Failed to decrypt message: {e}")
        return "[Message could not be decrypted - encryption key may have changed]"


class MessagingService:
    """Business logic for secure messaging"""

    @staticmethod
    def send_message(
        db: Session,
        sender_id: int,
        message_data: MessageCreate
    ) -> Message:
        """Send an encrypted message"""
        
        # Encrypt message content
        encrypted_content = encrypt_data(message_data.content)
        
        # Create message
        message = Message(
            sender_id=sender_id,
            recipient_id=message_data.recipient_id,
            subject=message_data.subject,
            encrypted_content=encrypted_content,
            is_emergency=message_data.is_emergency,
            parent_message_id=message_data.parent_message_id
        )
        
        db.add(message)
        db.commit()
        db.refresh(message)
        
        return message

    @staticmethod
    def get_inbox(
        db: Session,
        user_id: int,
        skip: int = 0,
        limit: int = 50,
        unread_only: bool = False
    ) -> tuple[List[Message], int, int]:
        """Get user's inbox messages"""
        query = db.query(Message).filter(Message.recipient_id == user_id)
        
        if unread_only:
            query = query.filter(Message.is_read == False)
        
        total = query.count()
        unread_count = db.query(Message).filter(
            Message.recipient_id == user_id,
            Message.is_read == False
        ).count()
        
        messages = query.order_by(Message.created_at.desc()).offset(skip).limit(limit).all()
        
        # Decrypt messages safely
        for message in messages:
            message.content = safe_decrypt(message.encrypted_content)
        
        return messages, total, unread_count

    @staticmethod
    def get_sent_messages(
        db: Session,
        user_id: int,
        skip: int = 0,
        limit: int = 50
    ) -> tuple[List[Message], int]:
        """Get user's sent messages"""
        query = db.query(Message).filter(Message.sender_id == user_id)
        
        total = query.count()
        messages = query.order_by(Message.created_at.desc()).offset(skip).limit(limit).all()
        
        # Decrypt messages safely
        for message in messages:
            message.content = safe_decrypt(message.encrypted_content)
        
        return messages, total

    @staticmethod
    def get_message_by_id(
        db: Session,
        message_id: int,
        user_id: int
    ) -> Message:
        """Get a specific message"""
        message = db.query(Message).filter(Message.id == message_id).first()
        
        if not message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )
        
        # Verify user is sender or recipient
        if message.sender_id != user_id and message.recipient_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this message"
            )
        
        # Decrypt message safely
        message.content = safe_decrypt(message.encrypted_content)
        
        # Mark as read if recipient
        if message.recipient_id == user_id and not message.is_read:
            message.is_read = True
            message.read_at = datetime.utcnow()
            db.commit()
        
        return message

    @staticmethod
    def delete_message(
        db: Session,
        message_id: int,
        user_id: int
    ) -> dict:
        """Delete a message"""
        message = db.query(Message).filter(Message.id == message_id).first()
        
        if not message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )
        
        # Only recipient can delete messages from inbox
        if message.recipient_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to delete this message"
            )
        
        db.delete(message)
        db.commit()
        
        return {"message": "Message deleted successfully"}

    @staticmethod
    def mark_as_read(
        db: Session,
        message_id: int,
        user_id: int
    ) -> Message:
        """Mark a message as read"""
        message = db.query(Message).filter(Message.id == message_id).first()
        
        if not message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )
        
        if message.recipient_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized"
            )
        
        if not message.is_read:
            message.is_read = True
            message.read_at = datetime.utcnow()
            db.commit()
            db.refresh(message)
        
        return message
