from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from fastapi_limiter.depends import RateLimiter
from config.database import get_db
from config.redis_db import redis_client
from models import User
from schemas import UserCreate, UserLogin, UserVerify, Token
from utils import (
    get_password_hash, 
    verify_password, 
    create_access_token, 
    generate_salt, 
    generate_verification_code,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from datetime import timedelta
import logging
import json

router = APIRouter(prefix="/auth", tags=["authentication"])
logger = logging.getLogger(__name__)

import resend
from pydantic import EmailStr
import os

# Configure Resend
resend.api_key = os.getenv("RESEND_API_KEY")

async def send_verification_email(email: EmailStr, code: str):
    """Send verification email using Resend"""
    
    html = f"""
    <html>
        <body>
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>Welcome to MediSecure!</h2>
                <p>Please use the following code to verify your email address:</p>
                <h1 style="color: #4CAF50; letter-spacing: 5px;">{code}</h1>
                <p>This code will expire in 10 minutes.</p>
                <p>If you did not request this, please ignore this email.</p>
            </div>
        </body>
    </html>
    """

    try:
        params = {
            "from": os.getenv("MAIL_FROM", "medisecure@resend.dev"),
            "to": [email],
            "subject": "MediSecure - Email Verification",
            "html": html,
        }

        email_response = resend.Emails.send(params)
        logger.info(f"Verification email sent to {email}. ID: {email_response}")
        
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        # Fallback to console for development if email fails
        print(f"FALLBACK - CODE: {code}")
            
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        # Fallback to console for development if email fails
        print(f"FALLBACK - CODE: {code}")

@router.post("/signup", status_code=status.HTTP_201_CREATED, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def signup(user: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 1. Check if user exists in DB
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # 2. Check if user has a pending registration in Redis
    redis_key = f"registration:{user.email}"
    existing_registration = await redis_client.get(redis_key)
    if existing_registration:
        raise HTTPException(status_code=400, detail="Verification code already sent. Please check your email.")

    # 3. Generate Salt and Hash Password
    salt = generate_salt()
    hashed_password = get_password_hash(user.password, salt)
    
    # 4. Generate Verification Code
    code = generate_verification_code()

    # 5. Prepare data for Redis
    user_data = {
        "email": user.email,
        "hashed_password": hashed_password,
        "salt": salt,
        "role": user.role.value,
        "code": code
    }
    
    # 6. Store in Redis (Expire in 10 minutes)
    await redis_client.setex(redis_key, 600, json.dumps(user_data))

    # 7. Send Email (Background Task)
    background_tasks.add_task(send_verification_email, user.email, code)

    return {"message": "Verification code sent. Please check your email."}

@router.post("/verify-email", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def verify_email(verification: UserVerify, db: Session = Depends(get_db)):
    # 1. Get data from Redis
    redis_key = f"registration:{verification.email}"
    stored_data_json = await redis_client.get(redis_key)

    if not stored_data_json:
        raise HTTPException(status_code=400, detail="Verification code expired or invalid")
    
    stored_data = json.loads(stored_data_json)
    
    # 2. Verify Code
    if stored_data["code"] != verification.code:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # 3. Create User in DB
    new_user = User(
        email=stored_data["email"],
        hashed_password=stored_data["hashed_password"],
        salt=stored_data["salt"],
        role=stored_data["role"],
        is_verified=True
    )
    
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database error during user creation")

    # 4. Delete data from Redis
    await redis_client.delete(redis_key)

    return {"message": "Email verified and user registered successfully"}

@router.post("/login", response_model=Token, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def login(user_credentials: UserLogin, db: Session = Depends(get_db)):
    # 1. Get User
    user = db.query(User).filter(User.email == user_credentials.email).first()
    if not user:
        raise HTTPException(status_code=403, detail="Invalid credentials")

    # 2. Check Verification
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    # 3. Verify Password (using stored salt)
    if not verify_password(user_credentials.password, user.salt, user.hashed_password):
        raise HTTPException(status_code=403, detail="Invalid credentials")

    # 4. Generate JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role.value},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}
