import redis.asyncio as redis
from .config import settings
import logging

logger = logging.getLogger(__name__)


class RedisClient:
    def __init__(self):
        self._client: redis.Redis = None

    async def connect(self) -> redis.Redis:
        """Initialize Redis connection"""
        if self._client is None:
            try:
                self._client = redis.Redis(
                    host=settings.redis_host,
                    port=settings.redis_port,
                    db=settings.redis_db,
                    password=settings.redis_password,
                    max_connections=settings.redis_max_connections,
                    decode_responses=True,
                    retry_on_timeout=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                )
                # Test connection
                await self._client.ping()
                logger.info("Redis connection established")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                # In development, continue without Redis but log warning
                if settings.debug:
                    logger.warning("Continuing without Redis - rate limiting will not work")
                    self._client = None
                else:
                    raise
        return self._client

    async def disconnect(self):
        """Close Redis connection"""
        if self._client:
            await self._client.close()
            self._client = None
            logger.info("Redis connection closed")

    @property
    def client(self) -> redis.Redis:
        """Get Redis client (must be connected first)"""
        if self._client is None:
            raise RuntimeError("Redis client not connected. Call connect() first.")
        return self._client


# Global instance
redis_client = RedisClient()