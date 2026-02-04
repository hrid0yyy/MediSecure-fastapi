from fastapi import FastAPI
from contextlib import asynccontextmanager
from routers import (
    users, auth, user_management, admin, 
    appointments, prescriptions, messaging, billing,
    # New routers
    auth_v2, dashboard, patients, doctors, records
)
# Import from root middleware.py file
from middleware import setup_middleware
# Import from middleware folder files
import sys
sys.path.insert(0, "middleware")
from audit import AuditLoggingMiddleware
from security import SecurityHeadersMiddleware, RequestSizeLimitMiddleware, IPBlockingMiddleware
sys.path.remove("middleware")
from fastapi_limiter import FastAPILimiter
from config.redis_db import redis_client
from config.database import engine, Base


# Create tables (for development purposes)
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await FastAPILimiter.init(redis_client)
    yield

app = FastAPI(
    title="MediSecure",
    description="Computer Security Project - Healthcare Data Management Platform",
    version="2.1.0",
    lifespan=lifespan
)

# Setup middleware
setup_middleware(app)
app.add_middleware(IPBlockingMiddleware)  # Check IP blocking first
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_request_size=10 * 1024 * 1024)  # 10 MB
app.add_middleware(AuditLoggingMiddleware)

# ============ NEW API ROUTES (/api/*) ============
# These match the frontend expectations

# Auth with HttpOnly cookies (/api/auth/*)
app.include_router(auth_v2.router)

# Dashboard API (/api/dashboard/*)
app.include_router(dashboard.router)

# Patients API (/api/patients/*)
app.include_router(patients.router)

# Doctors API (/api/doctors/*)
app.include_router(doctors.router)

# Medical Records API (/api/records/*)
app.include_router(records.router)

# Appointments API (/api/appointments/*)
from routers import appointments_v2
app.include_router(appointments_v2.router)

# ============ EXISTING ROUTES (for backward compatibility) ============

# Legacy auth at /auth/* (keep for backward compatibility)
app.include_router(auth.router)

# User management at /api/v1/users/*
app.include_router(user_management.router)

# Admin at /api/v1/admin/*
app.include_router(admin.router)

# Legacy users endpoints
app.include_router(users.router)

# Service routers at /api/v1/*
app.include_router(appointments.router)
app.include_router(prescriptions.router)
app.include_router(messaging.router)
app.include_router(billing.router)

@app.get("/")
async def root():
    """Root endpoint - returns welcome message"""
    return {
        "message": "Welcome to MediSecure!",
        "version": "2.1.0",
        "docs": "/docs",
        "redoc": "/redoc",
        "api_base": "/api"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": "2.1.0"}


