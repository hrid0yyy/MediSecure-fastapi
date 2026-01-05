# MediSecure - Implemented Features Documentation

## 📋 Project Overview

**Project Name:** MediSecure  
**Version:** 1.0.0  
**Description:** Computer Security Project - A secure medical application backend  
**Framework:** FastAPI (Python)  
**Last Updated:** January 2026

---

## 🏗️ Architecture Overview

### Technology Stack

| Component | Technology | Version/Details |
|-----------|------------|-----------------|
| Web Framework | FastAPI | Latest |
| Database | PostgreSQL | Via SQLAlchemy ORM |
| Cache/Session Store | Redis | Async Redis Client |
| Password Hashing | Argon2id | Via Passlib |
| JWT Authentication | python-jose | HS256 Algorithm |
| Rate Limiting | fastapi-limiter | Redis-backed |
| Email Service | Gmail SMTP | TLS Enabled |

### Project Structure

```
cs-project/
├── main.py                 # Application entry point
├── middleware.py           # Custom middleware (CORS, Logging)
├── dependencies.py         # Shared dependencies
├── init_db.py              # Database initialization script
├── requirements.txt        # Python dependencies
├── config/
│   ├── database.py         # PostgreSQL configuration
│   └── redis_db.py         # Redis configuration
├── models/
│   └── user.py             # SQLAlchemy models (User, UserDevice)
├── routers/
│   ├── auth.py             # Authentication endpoints
│   └── users.py            # User management endpoints
├── schemas/
│   ├── user.py             # Pydantic schemas for users
│   └── token.py            # Pydantic schemas for tokens
└── utils/
    └── security.py         # Security utilities
```

---

## 🔐 Security Features Implemented

### 1. Password Security

#### Argon2id Hashing
- **Implementation:** Using `passlib` with Argon2id scheme
- **Location:** `utils/security.py`
- **Features:**
  - Memory-hard algorithm resistant to GPU/ASIC attacks
  - Per-user unique salt generation (16 characters)
  - Salt appended to password before hashing
  - Automatic hash verification

```python
# Salt Generation
def generate_salt(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

# Password Hashing
def get_password_hash(password: str, salt: str) -> str:
    salted_password = password + salt
    return pwd_context.hash(salted_password)
```

### 2. JWT Authentication

- **Algorithm:** HS256
- **Token Expiry:** 300 minutes (5 hours)
- **Payload Contents:**
  - `sub`: User email
  - `role`: User role (patient, doctor, admin, staff)
  - `exp`: Expiration timestamp

### 3. Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/auth/signup` | 5 requests | 60 seconds |
| `/auth/verify-email` | 5 requests | 60 seconds |
| `/auth/login` | 5 requests | 60 seconds |
| `/auth/verify-device` | 5 requests | 60 seconds |
| `/auth/forgot-password` | 3 requests | 60 seconds |
| `/auth/reset-password` | 3 requests | 60 seconds |

**Implementation:** Redis-backed `fastapi-limiter`

### 4. Device Fingerprinting & Multi-Device Authentication

#### Device Fingerprint Generation
- Combines User-Agent header and Client IP
- SHA-256 hashed for privacy
- Stored per user in `user_devices` table

```python
def generate_device_fingerprint(request: Request) -> str:
    user_agent = request.headers.get("user-agent", "")
    client_ip = request.client.host if request.client else "unknown"
    raw_string = f"{user_agent}|{client_ip}"
    return hashlib.sha256(raw_string.encode()).hexdigest()
```

#### New Device Detection Flow
1. User attempts login from unknown device
2. System generates 6-digit verification code
3. Code stored in Redis (10-minute expiry)
4. Verification email sent to user
5. User verifies code from same device
6. Device fingerprint registered
7. JWT token issued

### 5. Email Verification System

#### Registration Flow
1. User submits email and password
2. System checks for existing user/pending registration
3. Generates salt and hashes password
4. Generates 6-digit verification code
5. Stores data in Redis (10-minute expiry)
6. Sends verification email via Gmail SMTP
7. User verifies code
8. User created in database with `is_verified=True`

### 6. Password Reset Flow

1. User requests password reset
2. System generates 6-digit code (stored in Redis, 10-min expiry)
3. Email sent with reset code
4. User submits code + new password
5. New salt generated, password re-hashed
6. User credentials updated

**Security Note:** Endpoint returns same message regardless of email existence to prevent user enumeration.

### 7. Request Logging

- **File:** `app.log`
- **Console:** StreamHandler
- **Logged Data:**
  - Client IP address
  - HTTP Method
  - Request path
  - Response status code
  - Request duration

### 8. CORS Configuration

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configured for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## 🗄️ Database Schema

### PostgreSQL Tables

#### `users` Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | Primary Key, Auto-increment | Unique user identifier |
| `email` | String | Unique, Indexed, Not Null | User email address |
| `hashed_password` | String | Not Null | Argon2id hashed password |
| `salt` | String | Not Null | Unique per-user salt |
| `role` | Enum | Default: 'patient' | User role (patient/doctor/admin/staff) |
| `is_verified` | Boolean | Default: False | Email verification status |

#### `user_devices` Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | Primary Key, Auto-increment | Unique device identifier |
| `user_id` | Integer | Foreign Key → users.id | Associated user |
| `fingerprint_hash` | String | Indexed, Not Null | SHA-256 device fingerprint |
| `last_login` | DateTime | Default: UTC Now | Last login timestamp |
| `created_at` | DateTime | Default: UTC Now | Device registration time |

### Redis Data Structures

| Key Pattern | Data | TTL | Purpose |
|-------------|------|-----|---------|
| `registration:{email}` | JSON (user data + code) | 600s | Pending registration |
| `device_verify:{email}` | JSON (fingerprint + code) | 600s | New device verification |
| `reset:{email}` | Verification code | 600s | Password reset |

---

## 🌐 API Endpoints

### Authentication Router (`/auth`)

| Method | Endpoint | Description | Rate Limit |
|--------|----------|-------------|------------|
| POST | `/auth/signup` | Register new user | 5/60s |
| POST | `/auth/verify-email` | Verify email with code | 5/60s |
| POST | `/auth/login` | User login (returns JWT) | 5/60s |
| POST | `/auth/verify-device` | Verify new device | 5/60s |
| POST | `/auth/forgot-password` | Request password reset | 3/60s |
| POST | `/auth/reset-password` | Reset password with code | 3/60s |

### Users Router (`/users`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users/` | List users (placeholder) |

### Root Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Welcome message with docs links |
| GET | `/health` | Health check endpoint |

---

## 📦 Request/Response Schemas

### User Schemas

```python
class UserCreate:
    email: EmailStr
    password: str

class UserLogin:
    email: EmailStr
    password: str

class UserVerify:
    email: EmailStr
    code: str

class UserForgotPassword:
    email: EmailStr

class UserResetPassword:
    email: EmailStr
    code: str
    new_password: str

class UserDeviceVerify:
    email: EmailStr
    code: str
```

### Token Schemas

```python
class Token:
    access_token: str
    token_type: str

class TokenData:
    email: Optional[str]
    role: Optional[str]
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_USER` | postgres | Database username |
| `POSTGRES_PASSWORD` | password | Database password |
| `POSTGRES_HOST` | localhost | Database host |
| `POSTGRES_PORT` | 5432 | Database port |
| `POSTGRES_DB` | cs_project_db | Database name |
| `REDIS_HOST` | localhost | Redis host |
| `REDIS_PORT` | 6379 | Redis port |
| `SECRET_KEY` | (default value) | JWT signing key |
| `GMAIL_EMAIL` | - | Gmail address for SMTP |
| `GMAIL_APP_PASSWORD` | - | Gmail app password |

---

## 📝 User Roles

| Role | Description |
|------|-------------|
| `patient` | Default role for new users |
| `doctor` | Medical professional |
| `admin` | System administrator |
| `staff` | Medical staff |

---

## 🔌 Dependencies

```
fastapi
uvicorn
pydantic
requests
redis
python-dotenv
sqlalchemy
psycopg2-binary
passlib[argon2]
argon2-cffi
python-jose[cryptography]
fastapi-limiter
email-validator
```

---

## 📊 Summary Statistics

| Category | Count |
|----------|-------|
| Authentication Endpoints | 6 |
| Database Tables | 2 |
| User Roles | 4 |
| Security Layers | 8+ |
| Redis Key Patterns | 3 |

---

## ✅ Security Checklist

- [x] Password hashing with Argon2id
- [x] Per-user salt generation
- [x] JWT-based authentication
- [x] Rate limiting on all auth endpoints
- [x] Email verification for new users
- [x] Device fingerprinting
- [x] Multi-device authentication (2FA via email)
- [x] Password reset flow
- [x] Request logging with IP tracking
- [x] CORS middleware
- [x] Redis-backed session management
- [x] Environment variable configuration
- [x] Async email sending (background tasks)
- [x] Secure password reset (no user enumeration)
