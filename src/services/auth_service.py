import secrets
import time
import hashlib
import hmac
import jwt
from typing import Optional, Dict, Any
import requests
from urllib.parse import urlencode
from ..core.redis_client import redis_client
from ..models.rate_limit import User, UserSession, AuthRequest, AuthResponse
from ..core.config import settings
import logging

logger = logging.getLogger(__name__)


class AuthService:
    """Authentication service for dashboard access"""

    def __init__(self):
        self.redis = redis_client
        self.jwt_secret = "sentinel-edge-jwt-secret-change-in-production"
        self.session_ttl = 86400 * 7  # 7 days

    async def authenticate_user(self, auth_request: AuthRequest) -> Optional[AuthResponse]:
        """Authenticate a user via email/password or OAuth"""
        try:
            client = await self.redis.connect()
            if not client:
                return None

            if auth_request.provider == "google":
                # Handle Google OAuth
                return await self._handle_google_auth(auth_request)
            else:
                # Handle email/password auth
                return await self._handle_email_auth(auth_request)

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    async def _handle_email_auth(self, auth_request: AuthRequest) -> Optional[AuthResponse]:
        """Handle email/password authentication"""
        try:
            client = await self.redis.connect()
            if not client:
                return None

            # Find user by email
            user_key = f"user:email:{auth_request.email}"
            user_id = await client.get(user_key)

            if not user_id:
                # User doesn't exist, create new user
                user = await self._create_user_from_email(auth_request.email)
            else:
                # Load existing user
                user_data = await client.get(f"user:{user_id}")
                if user_data:
                    user = User.parse_raw(user_data)
                else:
                    return None

            # Create session
            session = await self._create_session(user.id, "127.0.0.1", "Dashboard")

            return AuthResponse(user=user, session=session)

        except Exception as e:
            logger.error(f"Email auth error: {e}")
            return None

    async def _handle_google_auth(self, auth_request: AuthRequest) -> Optional[AuthResponse]:
        """Handle Google OAuth authentication with enhanced error handling"""
        try:
            logger.info(f"Handling Google OAuth for email: {auth_request.email}")

            # Validate required fields
            if not auth_request.email:
                logger.error("Google auth request missing email")
                return None

            client = await self.redis.connect()
            if not client:
                logger.error("Failed to connect to Redis for Google auth")
                return None

            # Create or get user with Google OAuth data
            logger.info(f"Creating/getting user for Google OAuth: {auth_request.email}")
            user = await self._create_or_get_user(
                auth_request.email,
                "google",
                auth_request.provider_id or auth_request.email,
                auth_request.name or auth_request.email.split('@')[0]
            )

            if not user:
                logger.error(f"Failed to create/get user for Google OAuth: {auth_request.email}")
                return None

            # Create session
            logger.info(f"Creating session for Google OAuth user: {user.id}")
            session = await self._create_session(user.id, "127.0.0.1", "Google OAuth")

            if not session:
                logger.error(f"Failed to create session for Google OAuth user: {user.id}")
                return None

            logger.info(f"Google OAuth authentication successful for: {auth_request.email}")
            return AuthResponse(user=user, session=session)

        except Exception as e:
            logger.error(f"Google auth error: {str(e)}", exc_info=True)
            return None

    async def exchange_google_code(self, code: str, state: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for Google access token and user info with comprehensive error handling"""
        try:
            # Validate configuration
            if not settings.google_oauth_client_id or not settings.google_oauth_client_secret:
                logger.error("Google OAuth not configured - missing client_id or client_secret")
                return None

            logger.info("Starting Google OAuth code exchange...")

            # Step 1: Exchange authorization code for access token
            token_url = "https://oauth2.googleapis.com/token"
            token_data = {
                "client_id": settings.google_oauth_client_id,
                "client_secret": settings.google_oauth_client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": settings.google_oauth_redirect_uri,
            }

            logger.info(f"Making token request to {token_url}")
            try:
                token_response = requests.post(token_url, data=token_data, timeout=10)
            except requests.exceptions.RequestException as req_error:
                logger.error(f"Token request failed with network error: {req_error}")
                return None

            if token_response.status_code != 200:
                logger.error(f"Token exchange failed with status {token_response.status_code}: {token_response.text}")
                return None

            try:
                token_info = token_response.json()
            except ValueError as json_error:
                logger.error(f"Failed to parse token response JSON: {json_error}")
                return None

            access_token = token_info.get("access_token")
            if not access_token:
                logger.error(f"No access token in response: {token_info}")
                return None

            logger.info("Successfully obtained access token")

            # Step 2: Get user info from Google
            user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}

            logger.info(f"Fetching user info from {user_info_url}")
            try:
                user_response = requests.get(user_info_url, headers=headers, timeout=10)
            except requests.exceptions.RequestException as req_error:
                logger.error(f"User info request failed with network error: {req_error}")
                return None

            if user_response.status_code != 200:
                logger.error(f"User info request failed with status {user_response.status_code}: {user_response.text}")
                return None

            try:
                user_info = user_response.json()
            except ValueError as json_error:
                logger.error(f"Failed to parse user info JSON: {json_error}")
                return None

            # Validate user info contains required fields
            if not user_info.get("email"):
                logger.error(f"User info missing email: {user_info}")
                return None

            logger.info(f"Successfully retrieved user info for: {user_info.get('email')}")

            return {
                "access_token": access_token,
                "user_info": user_info,
                "token_info": token_info
            }

        except Exception as e:
            logger.error(f"Google OAuth exchange error: {str(e)}", exc_info=True)
            return None

    def get_google_oauth_url(self, state: str = None) -> str:
        """Generate Google OAuth authorization URL"""
        if not settings.google_oauth_client_id:
            logger.error("Google OAuth client ID not configured")
            return "/auth/login?error=no_google_config"

        base_url = "https://accounts.google.com/o/oauth2/v2/auth"
        params = {
            "client_id": settings.google_oauth_client_id,
            "redirect_uri": settings.google_oauth_redirect_uri,
            "scope": "openid email profile",
            "response_type": "code",
            "access_type": "offline",
            "state": state or secrets.token_hex(16),
            "prompt": "consent"
        }

        oauth_url = f"{base_url}?{urlencode(params)}"
        logger.info(f"Generated Google OAuth URL: {oauth_url}")
        return oauth_url

    def get_oauth_config(self) -> Dict[str, Any]:
        """Get OAuth configuration status"""
        return {
            "configured": bool(settings.google_oauth_client_id and settings.google_oauth_client_secret),
            "client_id": settings.google_oauth_client_id[:10] + "..." if settings.google_oauth_client_id else None,
            "redirect_uri": settings.google_oauth_redirect_uri
        }

    async def _create_user_from_email(self, email: str) -> User:
        """Create a new user from email"""
        try:
            client = await self.redis.connect()
            if not client:
                raise Exception("Redis not available")

            user_id = f"user_{secrets.token_hex(8)}"
            user = User(
                id=user_id,
                email=email,
                name=email.split('@')[0],
                provider="email",
                provider_id=email,
                role="user",
                zones=[],  # Can access all zones for now
                created_at=int(time.time()),
                email_verified=False
            )

            # Store user
            await client.setex(f"user:{user_id}", 86400 * 365, user.json())
            await client.setex(f"user:email:{email}", 86400 * 365, user_id)

            logger.info(f"Created new user: {email}")
            return user

        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise

    async def _create_or_get_user(self, email: str, provider: str, provider_id: str, name: str) -> Optional[User]:
        """Create or get existing user with enhanced error handling"""
        try:
            logger.info(f"Creating/getting user - email: {email}, provider: {provider}, provider_id: {provider_id}")

            client = await self.redis.connect()
            if not client:
                logger.error("Redis not available for user creation")
                return None

            # Check if user exists by provider
            user_key = f"user:provider:{provider}:{provider_id}"
            user_id = await client.get(user_key)

            current_time = int(time.time())

            if user_id:
                # Load existing user
                logger.info(f"Found existing user by provider: {user_id}")
                user_data = await client.get(f"user:{user_id}")
                if user_data:
                    try:
                        user = User.parse_raw(user_data)
                        user.last_login = current_time
                        await client.setex(f"user:{user_id}", 86400 * 365, user.json())
                        logger.info(f"Updated existing user login time: {email}")
                        return user
                    except Exception as parse_error:
                        logger.error(f"Failed to parse existing user data: {parse_error}")
                        # Continue to create new user

            # Check if user exists by email (for email-based auth migration)
            email_key = f"user:email:{email}"
            existing_user_id = await client.get(email_key)

            if existing_user_id and not user_id:
                # User exists with different provider, link accounts
                logger.info(f"Linking existing user account: {email}")
                user_data = await client.get(f"user:{existing_user_id}")
                if user_data:
                    try:
                        user = User.parse_raw(user_data)
                        # Update with OAuth provider info
                        user.provider = provider
                        user.provider_id = provider_id
                        if name and not user.name:
                            user.name = name
                        user.last_login = current_time
                        user.email_verified = True

                        await client.setex(f"user:{existing_user_id}", 86400 * 365, user.json())
                        await client.setex(user_key, 86400 * 365, existing_user_id)
                        logger.info(f"Linked OAuth to existing user: {email}")
                        return user
                    except Exception as parse_error:
                        logger.error(f"Failed to parse/link existing user: {parse_error}")

            # Create new user
            user_id = f"user_{secrets.token_hex(8)}"
            logger.info(f"Creating new user with ID: {user_id}")

            user = User(
                id=user_id,
                email=email,
                name=name or email.split('@')[0],
                provider=provider,
                provider_id=provider_id,
                role="user",
                zones=[],  # Can access all zones for now
                created_at=current_time,
                last_login=current_time,
                email_verified=True  # OAuth users are pre-verified
            )

            # Store user with error handling
            try:
                await client.setex(f"user:{user_id}", 86400 * 365, user.json())
                await client.setex(user_key, 86400 * 365, user_id)
                await client.setex(email_key, 86400 * 365, user_id)
                logger.info(f"Successfully created new OAuth user: {email}")
                return user
            except Exception as redis_error:
                logger.error(f"Failed to store user in Redis: {redis_error}")
                return None

        except Exception as e:
            logger.error(f"Failed to create/get OAuth user: {str(e)}", exc_info=True)
            return None

    async def _create_session(self, user_id: str, ip_address: str, user_agent: str) -> Optional[UserSession]:
        """Create a new user session with enhanced error handling"""
        try:
            logger.info(f"Creating session for user: {user_id}")

            client = await self.redis.connect()
            if not client:
                logger.error("Redis not available for session creation")
                return None

            session_id = f"session_{secrets.token_hex(16)}"
            session_token = secrets.token_hex(32)
            current_time = int(time.time())

            session = UserSession(
                id=session_id,
                user_id=user_id,
                token=session_token,
                expires_at=current_time + self.session_ttl,
                created_at=current_time,
                ip_address=ip_address,
                user_agent=user_agent[:200]  # Truncate
            )

            # Store session with error handling
            try:
                await client.setex(f"session:{session_token}", self.session_ttl, session.json())
                await client.setex(f"user_sessions:{user_id}:{session_id}", self.session_ttl, session_token)
                logger.info(f"Successfully created session for user: {user_id}")
                return session
            except Exception as redis_error:
                logger.error(f"Failed to store session in Redis: {redis_error}")
                return None

        except Exception as e:
            logger.error(f"Failed to create session: {str(e)}", exc_info=True)
            return None

    async def validate_session(self, session_token: str) -> Optional[User]:
        """Validate a session token and return user"""
        try:
            client = await self.redis.connect()
            if not client:
                return None

            # Get session data
            session_data = await client.get(f"session:{session_token}")
            if not session_data:
                return None

            session = UserSession.parse_raw(session_data)

            # Check if session is expired
            if time.time() > session.expires_at:
                await client.delete(f"session:{session_token}")
                return None

            # Get user data
            user_data = await client.get(f"user:{session.user_id}")
            if not user_data:
                return None

            user = User.parse_raw(user_data)
            return user

        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return None

    async def logout_session(self, session_token: str):
        """Invalidate a session"""
        try:
            client = await self.redis.connect()
            if client:
                await client.delete(f"session:{session_token}")
                logger.info(f"Logged out session: {session_token}")
        except Exception as e:
            logger.error(f"Logout error: {e}")

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        try:
            client = await self.redis.connect()
            if client:
                user_data = await client.get(f"user:{user_id}")
                if user_data:
                    return User.parse_raw(user_data)
        except Exception as e:
            logger.error(f"Failed to get user {user_id}: {e}")
        return None