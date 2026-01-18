from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from fastapi_limiter.depends import RateLimiter
from config.database import get_db
from config.redis_db import redis_client
from models import User, UserDevice
from schemas import UserCreate, UserLogin, UserVerify, Token, UserForgotPassword, UserResetPassword, UserDeviceVerify
from utils import (
    get_password_hash,
    verify_password,
    create_access_token,
    generate_salt,
    generate_verification_code,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    generate_device_fingerprint
)
from utils.security import get_current_user
from datetime import datetime, timedelta
import logging
import json
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

router = APIRouter(prefix="/auth", tags=["authentication"])
logger = logging.getLogger(__name__)

from pydantic import EmailStr
import os

load_dotenv()

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

def _get_gmail_credentials():
    email = os.getenv("GMAIL_EMAIL")
    password = os.getenv("GMAIL_APP_PASSWORD")
    if not email or not password:
        raise ValueError("Gmail credentials are not configured. Set GMAIL_EMAIL and GMAIL_APP_PASSWORD.")
    return email, password

async def send_verification_email(email: EmailStr, code: str):
    """Send verification email using Gmail SMTP"""
    
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
        gmail_email, gmail_password = _get_gmail_credentials()
        message = EmailMessage()
        message["Subject"] = "MediSecure - Email Verification"
        message["From"] = gmail_email
        message["To"] = email
        message.set_content("Use the code above to verify your email.")
        message.add_alternative(html, subtype="html")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(gmail_email, gmail_password)
            server.send_message(message)
        logger.info(f"Verification email sent to {email} via Gmail.")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        print(f"FALLBACK - CODE: {code}")

async def send_password_reset_email(email: EmailStr, code: str):
    """Send password reset email using Gmail SMTP"""
    
    html = f"""
    <html>
        <body>
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>MediSecure Password Reset</h2>
                <p>You requested to reset your password. Use the code below:</p>
                <h1 style="color: #FF5722; letter-spacing: 5px;">{code}</h1>
                <p>This code will expire in 10 minutes.</p>
                <p>If you did not request this, please ignore this email.</p>
            </div>
        </body>
    </html>
    """

    try:
        gmail_email, gmail_password = _get_gmail_credentials()
        message = EmailMessage()
        message["Subject"] = "MediSecure - Password Reset"
        message["From"] = gmail_email
        message["To"] = email
        message.set_content("Use the code above to reset your password.")
        message.add_alternative(html, subtype="html")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(gmail_email, gmail_password)
            server.send_message(message)
        logger.info(f"Password reset email sent to {email} via Gmail.")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        print(f"FALLBACK - RESET CODE: {code}")

async def send_new_device_email(email: EmailStr, code: str):
    """Send new device verification email using Gmail SMTP"""
    
    html = f"""
    <html>
        <body>
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2>New Device Detected</h2>
                <p>We detected a login from a new device. Please verify it's you using the code below:</p>
                <h1 style="color: #2196F3; letter-spacing: 5px;">{code}</h1>
                <p>This code will expire in 10 minutes.</p>
                <p>If you did not attempt to login, please change your password immediately.</p>
            </div>
        </body>
    </html>
    """

    try:
        gmail_email, gmail_password = _get_gmail_credentials()
        message = EmailMessage()
        message["Subject"] = "MediSecure - New Device Verification"
        message["From"] = gmail_email
        message["To"] = email
        message.set_content("Use the code above to verify your new device.")
        message.add_alternative(html, subtype="html")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(gmail_email, gmail_password)
            server.send_message(message)
        logger.info(f"New device verification email sent to {email} via Gmail.")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        print(f"FALLBACK - DEVICE CODE: {code}")

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
        "role": "patient",  # Hardcoded to patient
        "code": code
    }
    
    # 6. Store in Redis (Expire in 10 minutes)
    await redis_client.setex(redis_key, 600, json.dumps(user_data))

    # 7. Send Email (Background Task)
    background_tasks.add_task(send_verification_email, user.email, code)

    return {"message": "Verification code sent. Please check your email."}

@router.post("/verify-email", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
@router.post("/verify", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def verify_email(verification: UserVerify, db: Session = Depends(get_db)):
    # 1. Get data from Redis
    redis_key = f"registration:{verification.email}"
    stored_data_json = await redis_client.get(redis_key)

    if not stored_data_json:
        raise HTTPException(status_code=400, detail="Verification code expired or invalid")
    
    stored_data = json.loads(stored_data_json)
    
    # 2. Verify Code (support both 'code' and 'verification_code' from frontend)
    submitted_code = verification.get_code
    if not submitted_code or stored_data["code"] != submitted_code:
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

@router.post("/login", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def login(user_credentials: UserLogin, request: Request, response: Response, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 1. Get User
    user = db.query(User).filter(User.email == user_credentials.email).first()
    if not user:
        raise HTTPException(status_code=403, detail="Invalid credentials")

    # 2. Check Verification
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    # 3. Verify Password (using stored salt)
    if not verify_password(user_credentials.password, user.hashed_password, user.salt):
        raise HTTPException(status_code=403, detail="Invalid credentials")

    # 4. Device Fingerprinting
    current_fingerprint = generate_device_fingerprint(request)
    
    # Check if user has any devices registered
    user_devices = db.query(UserDevice).filter(UserDevice.user_id == user.id).all()
    
    if not user_devices:
        # First login ever (or first since feature added) - register this device
        new_device = UserDevice(user_id=user.id, fingerprint_hash=current_fingerprint)
        db.add(new_device)
        db.commit()
    else:
        # Check if current fingerprint matches any known device
        known_device = next((d for d in user_devices if d.fingerprint_hash == current_fingerprint), None)
        
        if not known_device:
            # New device detected!
            # Generate verification code
            code = generate_verification_code()
            
            # Store in Redis (Expire in 10 minutes)
            redis_key = f"device_verify:{user.email}"
            await redis_client.setex(redis_key, 600, json.dumps({
                "fingerprint": current_fingerprint,
                "code": code
            }))
            
            # Send Email
            background_tasks.add_task(send_new_device_email, user.email, code)
            
            return JSONResponse(
                status_code=401,
                content={"detail": "New device detected. Please verify your device."},
                headers={"X-Device-Verification-Required": "true"},
                background=background_tasks
            )
        else:
            # Update last login for this device
            known_device.last_login = datetime.utcnow()
            db.commit()

    # 5. Generate JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value, "email": user.email},
        expires_delta=access_token_expires
    )

    # 6. Generate refresh token
    import secrets
    refresh_token = secrets.token_urlsafe(32)
    
    # Store refresh token in Redis (7 days)
    await redis_client.setex(
        f"refresh_token:{user.id}:{refresh_token}", 
        7 * 24 * 60 * 60,  # 7 days
        json.dumps({"user_id": user.id, "email": user.email})
    )

    # 7. Set HttpOnly cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,  # Set True in production with HTTPS
        samesite="lax",
        max_age=15 * 60,  # 15 minutes
        path="/"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=7 * 24 * 60 * 60,  # 7 days
        path="/"
    )

    # 8. Return response with token (also include in body for backward compatibility)
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role.value,
            "is_verified": user.is_verified
        },
        "message": "Login successful"
    }


@router.post("/refresh")
async def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Refresh access token using refresh token from HttpOnly cookie.
    
    POST /auth/refresh
    """
    # Get refresh token from cookie
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found"
        )
    
    try:
        # Find the refresh token in Redis
        # We need to find it by pattern since we store it with user_id prefix
        keys = await redis_client.keys(f"refresh_token:*:{refresh_token}")
        
        if not keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        # Get stored data
        stored_data_json = await redis_client.get(keys[0])
        if not stored_data_json:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expired"
            )
        
        stored_data = json.loads(stored_data_json)
        user_id = stored_data.get("user_id")
        
        # Get user from database
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        # Generate new access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"sub": str(user.id), "role": user.role.value, "email": user.email},
            expires_delta=access_token_expires
        )
        
        # Set new access token cookie
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=15 * 60,
            path="/"
        )
        
        return {
            "message": "Token refreshed successfully",
            "access_token": new_access_token,
            "token_type": "bearer"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token refresh failed"
        )


@router.post("/logout")
async def logout(request: Request, response: Response):
    """
    Logout user by clearing cookies and invalidating refresh token.
    
    POST /auth/logout
    """
    refresh_token = request.cookies.get("refresh_token")
    
    # Delete refresh token from Redis if exists
    if refresh_token:
        try:
            keys = await redis_client.keys(f"refresh_token:*:{refresh_token}")
            for key in keys:
                await redis_client.delete(key)
        except:
            pass
    
    # Clear cookies
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")
    
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_current_user_info(
    request: Request, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get current authenticated user's info.
    
    GET /auth/me
    """
    return {
        "id": current_user.id,
        "email": current_user.email,
        "name": current_user.name,
        "role": current_user.role.value,
        "is_verified": current_user.is_verified
    }

@router.post("/verify-device", dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def verify_device(verification: UserDeviceVerify, request: Request, db: Session = Depends(get_db)):
    # 1. Get data from Redis
    redis_key = f"device_verify:{verification.email}"
    stored_data_json = await redis_client.get(redis_key)

    if not stored_data_json:
        raise HTTPException(status_code=400, detail="Verification code expired or invalid")
    
    stored_data = json.loads(stored_data_json)
    
    # 2. Verify Code
    if stored_data["code"] != verification.code:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # 3. Verify Fingerprint matches (security check)
    current_fingerprint = generate_device_fingerprint(request)
    if stored_data["fingerprint"] != current_fingerprint:
        raise HTTPException(status_code=400, detail="Device fingerprint mismatch")

    # 4. Get User
    user = db.query(User).filter(User.email == verification.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 5. Register New Device
    new_device = UserDevice(user_id=user.id, fingerprint_hash=current_fingerprint)
    db.add(new_device)
    db.commit()

    # 6. Delete data from Redis
    await redis_client.delete(redis_key)

    # 7. Generate JWT (Login successful)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/forgot-password", dependencies=[Depends(RateLimiter(times=3, seconds=60))])
async def forgot_password(request: UserForgotPassword, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 1. Check if user exists
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        # For security, don't reveal if user exists or not
        return {"message": "If the email exists, a reset code has been sent."}

    # 2. Generate Reset Code
    code = generate_verification_code()

    # 3. Store in Redis (Expire in 10 minutes)
    redis_key = f"reset:{request.email}"
    await redis_client.setex(redis_key, 600, code)

    # 4. Send Email
    background_tasks.add_task(send_password_reset_email, request.email, code)

    return {"message": "If the email exists, a reset code has been sent."}

@router.post("/reset-password", dependencies=[Depends(RateLimiter(times=3, seconds=60))])
async def reset_password(request: UserResetPassword, db: Session = Depends(get_db)):
    # 1. Verify Code from Redis
    redis_key = f"reset:{request.email}"
    stored_code = await redis_client.get(redis_key)

    if not stored_code or stored_code != request.code:
        raise HTTPException(status_code=400, detail="Invalid or expired reset code")

    # 2. Get User
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 3. Hash New Password
    new_salt = generate_salt()
    new_hashed_password = get_password_hash(request.new_password, new_salt)

    # 4. Update User
    user.hashed_password = new_hashed_password
    user.salt = new_salt
    db.commit()

    # 5. Delete Code from Redis
    await redis_client.delete(redis_key)

    return {"message": "Password reset successfully"}


@router.post("/refresh")
async def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Refresh access token using refresh token from cookie.
    """
    from utils.security import decode_access_token
    
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token provided")
    
    # Find the refresh token in Redis
    pattern = f"refresh_token:*:{refresh_token}"
    keys = []
    async for key in redis_client.scan_iter(match=pattern):
        keys.append(key)
    
    if not keys:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    
    # Get user data from Redis
    token_data_json = await redis_client.get(keys[0])
    if not token_data_json:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    
    token_data = json.loads(token_data_json)
    user_id = token_data["user_id"]
    
    # Get user from DB
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Generate new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role.value, "email": user.email},
        expires_delta=access_token_expires
    )
    
    # Set new access token cookie
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=15 * 60,
        path="/"
    )
    
    return {"message": "Token refreshed successfully", "access_token": new_access_token}


@router.post("/logout")
async def logout(request: Request, response: Response):
    """
    Logout user and clear cookies.
    """
    # Try to delete refresh token from Redis
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        pattern = f"refresh_token:*:{refresh_token}"
        async for key in redis_client.scan_iter(match=pattern):
            await redis_client.delete(key)
    
    # Clear cookies
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")
    
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_current_user_info(request: Request, db: Session = Depends(get_db)):
    """
    Get current authenticated user info.
    """
    from utils.security import decode_access_token
    
    token = request.cookies.get("access_token")
    if not token:
        # Try Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role.value,
        "is_verified": user.is_verified,
        "is_active": user.is_active if hasattr(user, 'is_active') else True
    }

