from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse, HTMLResponse
from typing import Optional
import secrets
import urllib.parse
import logging
from ..models.rate_limit import AuthRequest, AuthResponse, User
from ..services.auth_service import AuthService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])


def get_auth_service():
    return AuthService()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Serve the login page - redirect if already authenticated"""
    # Check if user is already authenticated
    user = await get_current_user(request)
    if user:
        # User is already logged in, redirect to dashboard
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/dashboard", status_code=302)

    # User is not authenticated, show login page
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - SentinelEdge</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%);
                color: #f8fafc;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .login-container {
                background: #1a202c;
                border-radius: 16px;
                padding: 3rem;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                border: 1px solid #2d3748;
                width: 100%;
                max-width: 400px;
            }

            .login-header {
                text-align: center;
                margin-bottom: 2rem;
            }

            .login-header h1 {
                font-size: 2rem;
                font-weight: 700;
                margin-bottom: 0.5rem;
                background: linear-gradient(135deg, #f97316 0%, #ea580c 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            .login-header p {
                color: #a0aec0;
                font-size: 0.9rem;
            }

            .login-form {
                display: flex;
                flex-direction: column;
                gap: 1.5rem;
            }

            .form-group {
                display: flex;
                flex-direction: column;
                gap: 0.5rem;
            }

            .form-label {
                font-weight: 600;
                color: #f8fafc;
                font-size: 0.9rem;
            }

            .form-input {
                padding: 0.75rem;
                border: 2px solid #2d3748;
                border-radius: 8px;
                background: #0f1419;
                color: #f8fafc;
                font-size: 1rem;
                transition: border-color 0.3s;
            }

            .form-input:focus {
                outline: none;
                border-color: #f97316;
                box-shadow: 0 0 0 3px rgba(249, 115, 22, 0.1);
            }

            .login-btn {
                background: linear-gradient(135deg, #f97316 0%, #ea580c 100%);
                color: white;
                padding: 0.75rem;
                border: none;
                border-radius: 8px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.3s;
                margin-top: 1rem;
            }

            .login-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(249, 115, 22, 0.3);
            }

            .divider {
                text-align: center;
                margin: 1.5rem 0;
                position: relative;
                color: #a0aec0;
                font-size: 0.9rem;
            }

            .divider::before {
                content: '';
                position: absolute;
                top: 50%;
                left: 0;
                right: 0;
                height: 1px;
                background: #2d3748;
            }

            .divider span {
                background: #1a202c;
                padding: 0 1rem;
                position: relative;
                z-index: 1;
            }

            .google-btn {
                background: #2d3748;
                color: #f8fafc;
                padding: 0.75rem;
                border: 1px solid #4a5568;
                border-radius: 8px;
                font-size: 1rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 0.5rem;
                text-decoration: none;
            }

            .google-btn:hover {
                background: #4a5568;
                border-color: #f97316;
            }

            .back-link {
                text-align: center;
                margin-top: 2rem;
            }

            .back-link a {
                color: #f97316;
                text-decoration: none;
                font-size: 0.9rem;
            }

            .back-link a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>SentinelEdge</h1>
                <p>Enterprise Security Dashboard</p>
            </div>

            <form class="login-form" action="/auth/login" method="post">
                <div class="form-group">
                    <label class="form-label" for="email">Email</label>
                    <input type="email" id="email" name="email" class="form-input" required>
                </div>

                <div class="form-group">
                    <label class="form-label" for="password">Password</label>
                    <input type="password" id="password" name="password" class="form-input" required>
                </div>

                <button type="submit" class="login-btn">Sign In</button>
            </form>

            <div class="divider">
                <span>or</span>
            </div>

            <a href="/auth/google" class="google-btn">
                <svg width="18" height="18" viewBox="0 0 18 18">
                    <path fill="#4285F4" d="M16.51 8H8.98v3h4.3c-.18 1-.74 1.48-1.6 2.04v2.01h2.6a7.8 7.8 0 0 0 2.38-5.88c0-.57-.05-.66-.15-1.18z"/>
                    <path fill="#34A853" d="M8.98 17c2.16 0 3.97-.72 5.3-1.94l-2.6-2.01a4.8 4.8 0 0 1-2.7.75c-2.09 0-3.86-1.4-4.49-3.29H1.83v2.14A8 8 0 0 0 8.98 17z"/>
                    <path fill="#FBBC05" d="M4.49 10.52A4.77 4.77 0 0 1 4.24 9c0-.52.09-1.02.25-1.52V5.34H1.83A8 8 0 0 0 1 9c0 1.3.31 2.52.83 3.66l2.66-2.14z"/>
                    <path fill="#EA4335" d="M8.98 4.18c1.17 0 2.23.4 3.06 1.2l2.3-2.3A8 8 0 0 0 8.98 1 8 8 0 0 0 1.83 5.34L4.49 7.48C5.12 5.59 6.89 4.18 8.98 4.18z"/>
                </svg>
                Continue with Google
            </a>

            <div class="back-link">
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@router.post("/login")
async def login(
    request: Request,
    email: str = None,
    password: str = None,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Handle login authentication"""
    try:
        # For demo purposes, accept any email/password combination
        auth_request = AuthRequest(email=email or "demo@example.com", password=password, provider="email")

        auth_response = await auth_service.authenticate_user(auth_request)

        if auth_response:
            # Create redirect response with session cookie
            redirect_response = RedirectResponse(url="/dashboard", status_code=302)
            redirect_response.set_cookie(
                key="session_token",
                value=auth_response.session.token,
                httponly=True,
                max_age=86400 * 7,  # 7 days
                secure=False,  # Set to True in production with HTTPS
                samesite="lax",
                path="/"
            )
            return redirect_response
        else:
            return RedirectResponse(url="/auth/login?error=1", status_code=302)

    except Exception as e:
        logger.error(f"Login error: {e}")
        return RedirectResponse(url="/auth/login?error=1", status_code=302)


@router.get("/google")
async def google_oauth(auth_service: AuthService = Depends(get_auth_service)):
    """Initiate Google OAuth flow"""
    try:
        google_auth_url = auth_service.get_google_oauth_url()
        return RedirectResponse(url=google_auth_url)
    except Exception as e:
        logger.error(f"Google OAuth initiation error: {e}")
        return RedirectResponse(url="/auth/login?error=oauth_init", status_code=302)


@router.get("/google/callback")
async def google_oauth_callback(
    code: str,
    state: str,
    error: Optional[str] = None,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Handle Google OAuth callback with comprehensive error handling"""
    try:
        logger.info(f"OAuth callback received - code: {code[:10]}..., state: {state[:10]}...")

        # Handle OAuth errors from Google
        if error:
            logger.error(f"Google OAuth error: {error}")
            return RedirectResponse(url=f"/auth/login?error=oauth_{error}", status_code=302)

        # Validate required parameters
        if not code or not state:
            logger.error("Missing code or state parameter")
            return RedirectResponse(url="/auth/login?error=missing_params", status_code=302)

        # Step 1: Exchange authorization code for access token and user info
        logger.info("Exchanging authorization code for tokens...")
        oauth_result = await auth_service.exchange_google_code(code, state)

        if not oauth_result:
            logger.error("Failed to exchange authorization code")
            return RedirectResponse(url="/auth/login?error=token_exchange_failed", status_code=302)

        # Step 2: Extract user information
        user_info = oauth_result.get("user_info")
        if not user_info:
            logger.error("No user info in OAuth result")
            return RedirectResponse(url="/auth/login?error=no_user_info", status_code=302)

        email = user_info.get("email")
        name = user_info.get("name")
        google_id = user_info.get("id")

        logger.info(f"User info extracted - email: {email}, name: {name}, id: {google_id}")

        # Validate essential user information
        if not email:
            logger.error("No email in user info")
            return RedirectResponse(url="/auth/login?error=no_email", status_code=302)

        # Step 3: Create authentication request
        auth_request = AuthRequest(
            email=email,
            name=name or email.split('@')[0],  # Fallback to email prefix
            provider="google",
            provider_id=google_id or email
        )

        # Step 4: Authenticate/create user
        logger.info("Authenticating user...")
        auth_response = await auth_service.authenticate_user(auth_request)

        if not auth_response or not auth_response.user or not auth_response.session:
            logger.error("Authentication failed - no valid response")
            return RedirectResponse(url="/auth/login?error=auth_failed", status_code=302)

        logger.info(f"Authentication successful for user: {auth_response.user.email}")

        # Step 5: Create redirect response with session cookie
        redirect_response = RedirectResponse(url="/dashboard", status_code=302)

        try:
            redirect_response.set_cookie(
                key="session_token",
                value=auth_response.session.token,
                httponly=True,
                max_age=86400 * 7,  # 7 days
                secure=False,  # Set to True in production with HTTPS
                samesite="lax",
                path="/"
            )
            logger.info("Session cookie set successfully on redirect response")
        except Exception as cookie_error:
            logger.error(f"Failed to set session cookie: {cookie_error}")
            return RedirectResponse(url="/auth/login?error=cookie_error", status_code=302)

        # Step 6: Successful redirect to dashboard
        logger.info("Redirecting to dashboard with session cookie...")
        return redirect_response

    except Exception as e:
        logger.error(f"OAuth callback exception: {str(e)}", exc_info=True)
        # Don't expose internal errors to user
        return RedirectResponse(url="/auth/login?error=server_error", status_code=302)


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Handle logout"""
    session_token = request.cookies.get("session_token")
    if session_token:
        auth_service = AuthService()
        await auth_service.logout_session(session_token)

    # Clear session cookie
    response.delete_cookie(key="session_token")
    return RedirectResponse(url="/", status_code=302)


# Dependency to get current user
async def get_current_user(request: Request) -> Optional[User]:
    """Get current authenticated user from session"""
    session_token = request.cookies.get("session_token")
    if not session_token:
        return None

    auth_service = AuthService()
    user = await auth_service.validate_session(session_token)
    return user


# Dependency to require authentication
async def require_auth(request: Request) -> User:
    """Require authentication for protected routes"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": "/auth/login"}
        )
    return user


@router.get("/debug/session")
async def debug_session(request: Request):
    """Debug endpoint to check current session"""
    session_token = request.cookies.get("session_token")
    if not session_token:
        return {"status": "no_session", "message": "No session token found"}

    auth_service = AuthService()
    user = await auth_service.validate_session(session_token)

    if not user:
        return {"status": "invalid_session", "message": "Session token invalid or expired"}

    return {
        "status": "valid_session",
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "provider": user.provider,
            "role": user.role
        },
        "session_token": session_token[:10] + "..."
    }


@router.get("/me")
async def get_current_user_info(request: Request):
    """Get current user information"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    from datetime import datetime
    # Handle both integer timestamp and datetime object
    created_at = None
    if user.created_at:
        if isinstance(user.created_at, int):
            # Convert Unix timestamp to ISO format
            created_at = datetime.fromtimestamp(user.created_at).isoformat()
        else:
            # Already a datetime object
            created_at = user.created_at.isoformat()

    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "email_verified": user.email_verified,
        "created_at": created_at
    }


@router.get("/debug/oauth-test")
async def oauth_test():
    """Test OAuth configuration"""
    try:
        auth_service = AuthService()
        return {
            "oauth_configured": bool(settings.google_oauth_client_id and settings.google_oauth_client_secret),
            "client_id_set": bool(settings.google_oauth_client_id),
            "client_secret_set": bool(settings.google_oauth_client_secret),
            "redirect_uri": settings.google_oauth_redirect_uri,
            "client_id_prefix": settings.google_oauth_client_id[:10] + "..." if settings.google_oauth_client_id else None
        }
    except Exception as e:
        logger.error(f"OAuth debug error: {e}")
        return {
            "error": str(e),
            "oauth_configured": False
        }