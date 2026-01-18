import time
import logging
from fastapi import Request, FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

async def log_requests_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    client_ip = request.client.host if request.client else "Unknown"
    
    logger.info(
        f"IP: {client_ip} Method: {request.method} Path: {request.url.path} "
        f"Status: {response.status_code} Duration: {process_time:.4f}s"
    )
    return response

def setup_middleware(app: FastAPI):
    # CORS Middleware
    # When allow_credentials=True, you cannot use wildcard "*" for origins
    # Must specify explicit origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",  # Vite dev server
            "http://localhost:3000",  # Alternative dev server
            "http://127.0.0.1:5173",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Register Logging Middleware
    app.middleware("http")(log_requests_middleware)
