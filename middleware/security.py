from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
from sqlalchemy.orm import Session
from config.database import SessionLocal
from models.blocked_ip import BlockedIP

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    Implements best practices for web application security.
    """
    
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Prevent clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Strict Transport Security (HSTS) - force HTTPS
        # Enable this in production with HTTPS
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Content Security Policy (CSP)
        # Relax CSP for Swagger UI docs, strict for everything else
        if request.url.path in ["/docs", "/redoc", "/openapi.json"]:
            # Relaxed CSP for API documentation
            csp_policy = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https:; "
                "font-src 'self' data: https://cdn.jsdelivr.net; "
                "connect-src 'self'"
            )
        else:
            # Restrictive policy for all other endpoints
            csp_policy = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
        response.headers["Content-Security-Policy"] = csp_policy
        
        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions Policy (formerly Feature Policy)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )
        
        # Remove server header to avoid information disclosure
        if "server" in response.headers:
            del response.headers["server"]
        
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware to limit request body size to prevent DoS attacks.
    """
    
    def __init__(self, app, max_request_size: int = 10 * 1024 * 1024):  # 10 MB default
        super().__init__(app)
        self.max_request_size = max_request_size
    
    async def dispatch(self, request: Request, call_next):
        # Check Content-Length header
        content_length = request.headers.get("content-length")
        
        if content_length:
            content_length = int(content_length)
            if content_length > self.max_request_size:
                return Response(
                    content="Request body too large",
                    status_code=413,
                    media_type="text/plain"
                )
        
        return await call_next(request)


class IPBlockingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to block requests from blacklisted IP addresses.
    Checks the database for blocked IPs before processing requests.
    """
    
    async def dispatch(self, request: Request, call_next):
        # Get client IP address
        client_ip = self._get_client_ip(request)
        
        # Check if IP is blocked
        db: Session = SessionLocal()
        try:
            blocked_ip = db.query(BlockedIP).filter(
                BlockedIP.ip_address == client_ip,
                BlockedIP.is_active == True
            ).first()
            
            if blocked_ip:
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Access forbidden. Your IP address has been blocked.",
                        "ip": client_ip
                    }
                )
        finally:
            db.close()
        
        return await call_next(request)
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request.
        Checks X-Forwarded-For header first (for proxy/load balancer scenarios).
        """
        # Check X-Forwarded-For header (if behind proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Get the first IP in the chain (original client IP)
            return forwarded_for.split(",")[0].strip()
        
        # Check X-Real-IP header (alternative proxy header)
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fall back to direct client IP
        if request.client:
            return request.client.host
        
        return "unknown"
