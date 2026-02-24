import time
import math
from typing import Optional, Tuple, Dict, Any
import redis.asyncio as redis
from ..models.rate_limit import RateLimitConfig, RateLimitResult, RateLimitType
from ..core.redis_client import redis_client
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """Advanced rate limiter with multiple algorithms"""

    def __init__(self):
        self.redis = redis_client

    async def check_limit(
        self,
        identifier: str,
        config: RateLimitConfig
    ) -> RateLimitResult:
        """Check if request should be allowed based on rate limit config"""
        # Check if Redis is available
        try:
            client = await self.redis.connect()
            if client is None:
                # Redis not available - allow all requests in development
                logger.warning("Redis not available - allowing request")
                return RateLimitResult(
                    allowed=True,
                    remaining=config.max_requests,
                    reset_time=int(time.time()) + config.window_seconds,
                    limit=config.max_requests
                )
        except Exception:
            # Redis not available - allow all requests in development
            logger.warning("Redis connection failed - allowing request")
            return RateLimitResult(
                allowed=True,
                remaining=config.max_requests,
                reset_time=int(time.time()) + config.window_seconds,
                limit=config.max_requests
            )

        if config.type == RateLimitType.SLIDING_WINDOW:
            return await self._check_sliding_window(identifier, config)
        elif config.type == RateLimitType.TOKEN_BUCKET:
            return await self._check_token_bucket(identifier, config)
        elif config.type == RateLimitType.GOOGLE_ADAPTIVE:
            return await self._check_google_adaptive(identifier, config)
        else:
            return await self._check_fixed_window(identifier, config)

    async def _check_sliding_window(
        self,
        identifier: str,
        config: RateLimitConfig
    ) -> RateLimitResult:
        """Sliding window algorithm using Redis sorted sets"""
        client = await self.redis.connect()
        now = time.time()
        window_start = now - config.window_seconds

        # Use sorted set to store timestamps
        key = f"{config.key_prefix}:{identifier}"

        # Remove old entries outside the window
        await client.zremrangebyscore(key, 0, window_start)

        # Count current requests in window
        current_count = await client.zcard(key)

        # Calculate reset time (when oldest request expires)
        oldest_timestamp = await client.zrange(key, 0, 0, withscores=True)
        reset_time = int(now + config.window_seconds)
        if oldest_timestamp:
            reset_time = int(oldest_timestamp[0][1] + config.window_seconds)

        if current_count >= config.max_requests:
            # Calculate retry after time
            retry_after = reset_time - int(now)
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=reset_time,
                limit=config.max_requests,
                retry_after=max(0, retry_after)
            )

        # Add current request
        await client.zadd(key, {str(now): now})
        await client.expire(key, config.window_seconds)

        remaining = config.max_requests - current_count - 1

        return RateLimitResult(
            allowed=True,
            remaining=max(0, remaining),
            reset_time=reset_time,
            limit=config.max_requests
        )

    async def _check_token_bucket(
        self,
        identifier: str,
        config: RateLimitConfig
    ) -> RateLimitResult:
        """Token bucket algorithm"""
        client = await self.redis.connect()
        now = time.time()

        key = f"token_bucket:{config.key_prefix}:{identifier}"
        tokens_key = f"{key}:tokens"
        last_refill_key = f"{key}:last_refill"

        # Get current tokens and last refill time
        tokens_data = await client.mget(tokens_key, last_refill_key)
        current_tokens = float(tokens_data[0] or config.burst_allowance or config.max_requests)
        last_refill = float(tokens_data[1] or now)

        # Calculate tokens to add since last refill
        time_passed = now - last_refill
        refill_rate = config.refill_rate or (config.max_requests / config.window_seconds)
        tokens_to_add = time_passed * refill_rate

        # Add tokens up to burst limit
        burst_limit = config.burst_allowance or config.max_requests
        new_tokens = min(current_tokens + tokens_to_add, burst_limit)

        # Check if we can consume a token
        if new_tokens >= 1:
            new_tokens -= 1
            allowed = True
            remaining = math.floor(new_tokens)
        else:
            allowed = False
            remaining = 0

        # Update Redis
        await client.mset({
            tokens_key: new_tokens,
            last_refill_key: now
        })

        # Set expiration
        await client.expire(tokens_key, config.window_seconds * 2)
        await client.expire(last_refill_key, config.window_seconds * 2)

        reset_time = int(now + config.window_seconds)

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_time=reset_time,
            limit=config.max_requests,
            retry_after=0 if allowed else 1
        )

    async def _check_fixed_window(
        self,
        identifier: str,
        config: RateLimitConfig
    ) -> RateLimitResult:
        """Simple fixed window algorithm"""
        client = await self.redis.connect()
        now = int(time.time())
        window_start = (now // config.window_seconds) * config.window_seconds

        key = f"fixed:{config.key_prefix}:{identifier}:{window_start}"

        # Get current count
        current_count = int(await client.get(key) or 0)

        if current_count >= config.max_requests:
            reset_time = window_start + config.window_seconds
            retry_after = reset_time - now
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=reset_time,
                limit=config.max_requests,
                retry_after=max(0, retry_after)
            )

        # Increment counter
        await client.incr(key)
        await client.expire(key, config.window_seconds)

        return RateLimitResult(
            allowed=True,
            remaining=config.max_requests - current_count - 1,
            reset_time=window_start + config.window_seconds,
            limit=config.max_requests
        )

    async def _check_google_adaptive(
        self,
        identifier: str,
        config: RateLimitConfig
    ) -> RateLimitResult:
        """Google-style adaptive rate limiting with traffic shaping"""
        now = int(time.time())
        window_key = f"{identifier}:adaptive:{now // config.window_seconds}"

        try:
            # Get Redis client
            client = await self.redis.connect()
            if client is None:
                return RateLimitResult(
                    allowed=True,
                    remaining=config.max_requests,
                    reset_time=now + config.window_seconds,
                    limit=config.max_requests
                )

            # Get current request count
            current_count = int(await client.get(window_key) or 0)

            # Check if we should allow burst traffic (first few requests)
            burst_allowance = getattr(config, 'burst_allowance', 10)

            # Adaptive algorithm: allow more requests during low traffic periods
            traffic_load = await self._calculate_traffic_load(identifier, config)
            adaptive_limit = self._calculate_adaptive_limit(config.max_requests, traffic_load) or config.max_requests

            # Allow burst traffic or check against adaptive limit
            if current_count < burst_allowance or current_count < adaptive_limit:
                # Increment counter
                new_count = await client.incr(window_key)
                await client.expire(window_key, config.window_seconds * 2)

                # Calculate remaining requests
                remaining = max(0, adaptive_limit - new_count)

                return RateLimitResult(
                    allowed=True,
                    remaining=remaining,
                    reset_time=(now // config.window_seconds + 1) * config.window_seconds,
                    limit=adaptive_limit
                )
            else:
                # Rate limit exceeded
                reset_time = (now // config.window_seconds + 1) * config.window_seconds
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=reset_time,
                    limit=adaptive_limit
                )

        except Exception as e:
            logger.error(f"Google adaptive rate limiting error: {e}")
            # Fallback to basic allowing
            return RateLimitResult(
                allowed=True,
                remaining=config.max_requests,
                reset_time=now + config.window_seconds,
                limit=config.max_requests
            )

    async def _calculate_traffic_load(self, identifier: str, config: RateLimitConfig) -> float:
        """Calculate current traffic load for adaptive rate limiting"""
        try:
            now = int(time.time())
            # Check traffic over last 5 windows
            total_requests = 0
            client = await self.redis.connect()
            if client is None:
                return 0.5

            for i in range(5):
                window_start = (now - i * config.window_seconds) // config.window_seconds
                window_key = f"{identifier}:adaptive:{window_start}"
                count = int(await client.get(window_key) or 0)
                total_requests += count

            # Calculate load factor (0-1, where 1 is high traffic)
            avg_requests = total_requests / 5
            load_factor = min(1.0, avg_requests / config.max_requests)
            return load_factor

        except Exception:
            return 0.5  # Default medium load

    def _calculate_adaptive_limit(self, base_limit: int, traffic_load: float) -> int:
        """Calculate adaptive limit based on traffic load"""
        if traffic_load < 0.3:
            # Low traffic - allow 150% of base limit
            return int(base_limit * 1.5)
        elif traffic_load < 0.7:
            # Medium traffic - base limit
            return base_limit
        else:
            # High traffic - reduce to 70% of base limit
            return max(1, int(base_limit * 0.7))

    async def get_advanced_stats(self, key_prefix: str) -> Dict[str, Any]:
        """Get advanced analytics like Google provides"""
        try:
            client = await self.redis.connect()
            if client is None:
                return {}

            # Get all keys matching the prefix
            keys = await client.keys(f"{key_prefix}:*")

            total_requests = 0
            active_keys = len(keys)
            request_counts = []
            time_windows = []

            for key in keys:
                try:
                    count = int(await client.get(key) or 0)
                    if count:
                        total_requests += count
                        request_counts.append(count)

                        # Extract timestamp from key if it's a time-based key
                        key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)
                        if ':adaptive:' in key_str or ':sliding:' in key_str or ':token:' in key_str:
                            try:
                                parts = key_str.split(':')
                                if len(parts) > 2 and parts[-1].isdigit():
                                    time_windows.append(int(parts[-1]))
                            except:
                                pass
                except:
                    pass

            # Calculate statistics
            avg_requests = total_requests / max(1, len(request_counts)) if request_counts else 0
            max_requests = max(request_counts) if request_counts else 0
            min_requests = min(request_counts) if request_counts else 0

            # Calculate request patterns
            if time_windows:
                time_windows.sort()
                time_span = max(time_windows) - min(time_windows) if time_windows else 0
                requests_per_second = total_requests / max(1, time_span) if time_span > 0 else 0
            else:
                requests_per_second = 0

            # Traffic health score (0-100)
            health_score = min(100, max(0, 100 - (total_requests / 1000) * 10))

            return {
                "total_requests": total_requests,
                "active_keys": active_keys,
                "avg_requests_per_key": avg_requests,
                "max_requests_in_window": max_requests,
                "min_requests_in_window": min_requests,
                "requests_per_second": requests_per_second,
                "time_windows_covered": len(set(time_windows)),
                "traffic_health_score": health_score,
                "traffic_trend": "stable",  # Could be enhanced to detect trends
                "peak_usage_percentage": (max_requests / max(1, avg_requests)) * 100 if avg_requests > 0 else 0
            }

        except Exception as e:
            logger.error(f"Error getting advanced stats: {e}")
            return {}

    async def get_stats(self, key_prefix: str) -> dict:
        """Get usage statistics for monitoring"""
        try:
            client = await self.redis.connect()
            if client is None:
                # Redis not available
                return {
                    "total_requests": 0,
                    "key_usage": {},
                    "active_keys": 0,
                    "redis_available": False
                }
        except Exception:
            return {
                "total_requests": 0,
                "key_usage": {},
                "active_keys": 0,
                "redis_available": False
            }

        # Get all keys matching the prefix pattern
        pattern = f"{key_prefix}:*"
        keys = await client.keys(pattern)

        total_requests = 0
        key_usage = {}

        for key in keys:
            if "token_bucket" in key:
                continue  # Skip token bucket internal keys

            # Check actual Redis key type instead of key name pattern
            key_type = await client.type(key)
            if key_type == "zset":
                count = await client.zcard(key)
            elif key_type == "string":
                count = int(await client.get(key) or 0)
            else:
                count = 0  # Unknown type

            total_requests += count
            key_usage[key] = count

        return {
            "total_requests": total_requests,
            "key_usage": key_usage,
            "active_keys": len(keys),
            "redis_available": True
        }