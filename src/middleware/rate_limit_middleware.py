import time
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Callable, Dict, Optional, Any
import logging
from ..services.rate_limiter import RateLimiter
from ..services.bot_detector import BotDetector
from ..services.zone_service import ZoneService
from ..models.rate_limit import RateLimitConfig, RateLimitType, Zone
from ..core.config import settings

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Multi-tenant middleware for zone-based security with bot detection"""

    def __init__(self, app, rate_limiter: Optional[RateLimiter] = None, bot_detector: Optional[BotDetector] = None, zone_service: Optional[ZoneService] = None):
        super().__init__(app)
        self.rate_limiter = rate_limiter or RateLimiter()
        self.bot_detector = bot_detector or BotDetector()
        self.zone_service = zone_service or ZoneService()
        self._default_configs = self._build_default_configs()

    def _build_default_configs(self) -> Dict[str, RateLimitConfig]:
        """Build default rate limit configurations"""
        return {
            "global": RateLimitConfig(
                key_prefix="global",
                max_requests=settings.default_max_requests,
                window_seconds=settings.default_window_seconds,
                type=RateLimitType.SLIDING_WINDOW
            ),
            "api": RateLimitConfig(
                key_prefix="api",
                max_requests=1000,
                window_seconds=60,
                type=RateLimitType.SLIDING_WINDOW
            ),
            "auth": RateLimitConfig(
                key_prefix="auth",
                max_requests=5,
                window_seconds=300,  # 5 minutes
                type=RateLimitType.FIXED_WINDOW
            )
        }

    def _get_client_identifier(self, request: Request) -> str:
        """Extract client identifier from request"""
        # Try different identification methods
        client_ip = self._get_client_ip(request)
        user_id = request.headers.get("X-User-ID")
        api_key = request.headers.get("X-API-Key")

        # Priority: user_id > api_key > ip
        if user_id:
            return f"user:{user_id}"
        elif api_key:
            return f"apikey:{api_key}"
        else:
            return f"ip:{client_ip}"

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        # Check various headers for real IP
        headers_to_check = [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "X-Client-IP"
        ]

        for header in headers_to_check:
            ip = request.headers.get(header)
            if ip:
                # Take first IP if comma-separated
                return ip.split(",")[0].strip()

        # Fallback to direct client
        return request.client.host if request.client else "unknown"

    def _get_route_config(self, path: str, method: str) -> RateLimitConfig:
        """Get appropriate rate limit config for route"""
        # Auth endpoints get stricter limits
        if path.startswith("/auth") or path.startswith("/login"):
            return self._default_configs["auth"]

        # API endpoints
        if path.startswith("/api"):
            return self._default_configs["api"]

        # Default global limit
        return self._default_configs["global"]

    async def _get_request_zone(self, request: Request) -> Optional[Zone]:
        """Extract zone information from request headers"""
        # Check for X-Zone-Key header
        zone_key = request.headers.get("X-Zone-Key")
        if zone_key:
            zone = await self.zone_service.get_zone_by_key(zone_key)
            if zone and zone.status == "active":
                return zone

        # Check for zone in query parameters (for development/testing)
        zone_id = request.query_params.get("zone_id")
        if zone_id:
            zone = await self.zone_service.get_zone(zone_id)
            if zone and zone.status == "active":
                return zone

        # No zone specified - use default/global behavior
        return None

    def _get_zone_bot_config(self, zone_config) -> Dict[str, Any]:
        """Get bot detection config for zone (fallback to global)"""
        if zone_config and hasattr(zone_config, 'bot_protection'):
            return zone_config.bot_protection
        return {
            "enabled": settings.enable_bot_detection,
            "suspicious_threshold": settings.bot_suspicious_threshold,
            "challenge_threshold": settings.bot_challenge_threshold,
            "block_threshold": settings.bot_block_threshold
        }

    def _get_zone_rate_config(self, zone_config) -> Dict[str, Any]:
        """Get rate limiting config for zone (fallback to global)"""
        if zone_config and hasattr(zone_config, 'rate_limit'):
            return zone_config.rate_limit
        return {
            "enabled": True,
            "requests": settings.default_max_requests,
            "per_seconds": settings.default_window_seconds
        }

    def _get_zone_challenge_config(self, zone_config) -> Dict[str, Any]:
        """Get challenge config for zone (fallback to global)"""
        if zone_config and hasattr(zone_config, 'challenge'):
            return zone_config.challenge
        return {
            "pow_difficulty": settings.challenge_difficulty,
            "timeout_seconds": settings.challenge_timeout_seconds,
            "trust_ttl_seconds": settings.verification_trust_seconds
        }

    def _get_recommendation_from_config(self, score: int, bot_config: Dict[str, Any]) -> str:
        """Get action recommendation based on zone config thresholds"""
        if score >= bot_config.get("block_threshold", 70):
            return 'block'
        elif score >= bot_config.get("challenge_threshold", 50):
            return 'challenge'
        elif score >= bot_config.get("suspicious_threshold", 30):
            return 'monitor'
        else:
            return 'allow'

    async def dispatch(self, request: Request, call_next):
        """Process each request through zone-based security with bot detection"""
        start_time = time.time()

        try:
            # Skip security checks for certain paths
            skip_paths = ['/challenge', '/dashboard', '/docs', '/redoc', '/openapi.json', '/favicon.ico', '/zones', '/auth/debug', '/auth/login', '/auth/google']
            should_skip = any(request.url.path.startswith(path) for path in skip_paths)

            # Get zone information from request
            zone = await self._get_request_zone(request)
            zone_config = None

            if zone:
                zone_config = await self.zone_service.get_zone_config(zone.id)
                # Store zone info in request state for later use
                request.state.zone = zone
                request.state.zone_config = zone_config

            if not should_skip:
                # Check if client is already verified (passed challenge recently)
                is_verified = await self.bot_detector.is_verified(request)

                # Get zone-specific bot configuration
                bot_config = self._get_zone_bot_config(zone_config)

                if bot_config.get("enabled", True):
                    # Perform bot analysis with zone-specific thresholds
                    analysis = await self.bot_detector.analyze_request(request)

                    # Override classification based on zone thresholds
                    score = analysis['score']
                    if score >= bot_config.get("block_threshold", 70):
                        classification = 'block'
                    elif score >= bot_config.get("challenge_threshold", 50):
                        classification = 'challenge'
                    elif score >= bot_config.get("suspicious_threshold", 30):
                        classification = 'suspicious'
                    else:
                        classification = 'legitimate'

                    analysis['classification'] = classification
                    analysis['recommendation'] = self._get_recommendation_from_config(score, bot_config)

                    # Add bot analysis headers
                    request.state.bot_analysis = analysis

                    # Handle bot classification
                    if classification == 'block':
                        zone_info = f" [zone:{zone.id}]" if zone else ""
                        logger.warning(
                            f"Blocked suspected bot {self._get_client_identifier(request)}{zone_info}: "
                            f"score={score}, signals={analysis['signals']}"
                        )
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "Forbidden",
                                "message": "Request blocked by security system",
                                "bot_score": score,
                                "zone": zone.id if zone else None
                            }
                        )

                    elif classification == 'challenge':
                        # Get zone-specific challenge config
                        challenge_config = self._get_zone_challenge_config(zone_config)

                        # Generate challenge with zone-specific settings
                        challenge = await self.bot_detector.generate_challenge(request, challenge_config)

                        zone_info = f" [zone:{zone.id}]" if zone else ""
                        logger.info(
                            f"Challenging suspected bot {self._get_client_identifier(request)}{zone_info}: "
                            f"score={score}"
                        )

                        # Check if this is a browser request
                        accept_html = 'text/html' in request.headers.get('accept', '')
                        if accept_html and request.method == 'GET':
                            # Redirect to challenge page
                            return RedirectResponse(
                                url=f"/challenge/page/{challenge['id']}",
                                status_code=302
                            )
                        else:
                            # Return JSON challenge for API clients
                            return JSONResponse(
                                status_code=429,
                                content={
                                    "error": "Challenge Required",
                                    "message": "Complete the security challenge to continue",
                                    "challenge": challenge,
                                    "bot_score": score,
                                    "zone": zone.id if zone else None
                                },
                                headers={"X-Challenge-Required": "true"}
                            )

            # Get zone-specific rate limiting config
            rate_config = self._get_zone_rate_config(zone_config)

            if rate_config.get("enabled", True):
                # Create zone-aware rate limit config
                config = RateLimitConfig(
                    key_prefix=f"zone_{zone.id}_" if zone else "global_",
                    max_requests=rate_config.get("requests", settings.default_max_requests),
                    window_seconds=rate_config.get("per_seconds", settings.default_window_seconds),
                    burst_allowance=rate_config.get("burst_allowance", None)
                )

                # Get client identifier (zone-aware)
                identifier = self._get_client_identifier(request)

                # Check rate limit
                result = await self.rate_limiter.check_limit(identifier, config)
                rate_limit_applied = True
            else:
                # Rate limiting disabled for this zone
                result = None
                rate_limit_applied = False

            # Add rate limit headers to response
            response = await call_next(request)

            # Add zone information
            if zone:
                response.headers["X-Zone-ID"] = zone.id
                response.headers["X-Zone-Name"] = zone.name

            # Add rate limit headers if rate limiting was applied
            if rate_limit_applied and result:
                response.headers["X-RateLimit-Limit"] = str(result.limit)
                response.headers["X-RateLimit-Remaining"] = str(result.remaining)
                response.headers["X-RateLimit-Reset"] = str(result.reset_time)

            # Add bot analysis headers if available
            if hasattr(request.state, 'bot_analysis'):
                analysis = request.state.bot_analysis
                response.headers["X-Bot-Score"] = str(analysis['score'])
                response.headers["X-Bot-Classification"] = analysis['classification']

            if rate_limit_applied and result and not result.allowed:
                # Request was blocked by rate limiting
                zone_info = f" [zone:{zone.id}]" if zone else ""
                logger.warning(
                    f"Rate limit exceeded for {identifier} on {request.url.path}{zone_info}. "
                    f"Limit: {result.limit}, Remaining: {result.remaining}"
                )

                # Check if this is an API request that should get CAPTCHA challenge
                user_agent = request.headers.get('user-agent', '').lower()
                accept_header = request.headers.get('accept', '')

                # For browser requests (HTML), redirect to challenge page
                is_browser_request = (
                    'text/html' in accept_header and
                    not request.url.path.startswith('/api/') and
                    not 'xmlhttprequest' in user_agent
                )

                if is_browser_request:
                    # Redirect browser users to rate limit challenge page
                    logger.info(f"Redirecting browser request to rate limit challenge page: {identifier}")
                    return RedirectResponse(
                        url="/challenge/dashboard-captcha-page",
                        status_code=302
                    )

                # For API requests (JSON/XMLHttpRequest), provide CAPTCHA challenge
                is_api_request = (
                    'application/json' in accept_header or
                    request.url.path.startswith('/api/') or
                    'xmlhttprequest' in user_agent
                )

                if is_api_request:
                    # Generate CAPTCHA challenge for API rate limit violations
                    challenge_config = self._get_zone_challenge_config(zone_config)

                    try:
                        challenge = await self.bot_detector.generate_challenge(request, challenge_config)
                        logger.info(
                            f"Generated CAPTCHA challenge for rate-limited API request: {identifier} on {request.url.path}"
                        )

                        return JSONResponse(
                            status_code=429,
                            content={
                                "error": "Rate Limit Exceeded - CAPTCHA Required",
                                "message": "Too many requests. Complete the CAPTCHA challenge to continue.",
                                "requires_captcha": True,
                                "challenge": challenge,
                                "retry_after": result.retry_after,
                                "limit": result.limit,
                                "remaining": result.remaining,
                                "reset_time": result.reset_time,
                                "zone": zone.id if zone else None
                            },
                            headers={
                                "Retry-After": str(result.retry_after or 60),
                                "X-RateLimit-Limit": str(result.limit),
                                "X-RateLimit-Remaining": str(result.remaining),
                                "X-RateLimit-Reset": str(result.reset_time),
                                "X-Captcha-Required": "true"
                            }
                        )
                    except Exception as challenge_error:
                        logger.error(f"Failed to generate CAPTCHA challenge: {challenge_error}")
                        # Fall back to standard rate limit response

                # Return standard 429 Too Many Requests for non-API requests
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Too Many Requests",
                        "message": "Rate limit exceeded. Please try again later.",
                        "retry_after": result.retry_after,
                        "limit": result.limit,
                        "remaining": result.remaining,
                        "reset_time": result.reset_time,
                        "zone": zone.id if zone else None
                    },
                    headers={
                        "Retry-After": str(result.retry_after or 60),
                        "X-RateLimit-Limit": str(result.limit),
                        "X-RateLimit-Remaining": str(result.remaining),
                        "X-RateLimit-Reset": str(result.reset_time)
                    }
                )

            # Log successful request
            processing_time = time.time() - start_time
            zone_info = f" [zone:{zone.id}]" if zone else ""
            bot_info = ""
            if hasattr(request.state, 'bot_analysis'):
                analysis = request.state.bot_analysis
                bot_info = f" [bot_score={analysis['score']}]"

            logger.info(
                f"Request allowed for {identifier}: {request.method} {request.url.path} "
                f"({processing_time:.3f}s){zone_info}{bot_info}"
            )

            return response

        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            # On error, allow the request to proceed
            return await call_next(request)