import redis.asyncio as redis
import os
from dotenv import load_dotenv

load_dotenv()

def get_redis_client():
    redis_host = os.getenv("REDIS_HOST", "localhost")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    return redis.Redis(host=redis_host, port=redis_port, db=0, decode_responses=True)

# Create a single instance to be imported
redis_client = get_redis_client()
